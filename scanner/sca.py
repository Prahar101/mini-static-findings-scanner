"""
Software Composition Analysis: find known-vulnerable dependencies.

Parses the dependency manifests (requirements.txt, package.json,
package-lock.json) and asks the public OSV.dev API whether each pinned
(name, version) has a known advisory. OSV does the version-range match on its
side, which avoids the usual SCA false positive of flagging a package that is
only vulnerable in some other version.

It sticks to stdlib urllib, so there's no requests dependency. Offline mode
skips the network and still reports unpinned deps. Network and parse errors are
caught so a bad manifest or no internet never crashes the scan, and a version
we can't pin down is reported at low confidence.
"""

import json
import os
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from scanner.rules import IGNORE_DIRS
from scanner.schema import HIGH, LOW, MED, Finding

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10

ECOSYSTEM_LANGUAGE = {"PyPI": "Python", "npm": "JavaScript"}

try:  # use packaging for PEP 440 version parsing when it's installed
    from packaging.requirements import Requirement
    HAS_PACKAGING = True
except Exception:  
    HAS_PACKAGING = False

@dataclass
class Dependency:
    ecosystem: str  
    name: str
    version: Optional[str]
    pinned: bool
    file: str
    line: int

def find_manifests(root: Path) -> List[Path]:
    names = {"requirements.txt", "package.json", "package-lock.json"}
    found: List[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.name in names:
            found.append(path)
    return found


def _read_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def parse_requirements(path: Path, rel: str) -> List[Dependency]:
    deps: List[Dependency] = []
    for line_no, raw in enumerate(_read_lines(path), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name, version, pinned = _parse_requirement_line(line)
        if name:
            deps.append(Dependency("PyPI", name, version, pinned, rel, line_no))
    return deps


def _parse_requirement_line(line: str):
    if HAS_PACKAGING:
        try:
            req = Requirement(line)
            version, pinned = None, False
            for spec in req.specifier:
                if spec.operator in ("==", "==="):
                    version, pinned = spec.version, True
                    break
            return req.name, version, pinned
        except Exception:
            pass
    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==)?\s*([0-9][^\s;,]*)?", line)
    if not m:
        return None, None, False
    name, eq, version = m.group(1), m.group(2), m.group(3)
    pinned = bool(eq and version)
    return name, (version if pinned else None), pinned


def parse_package_json(path: Path, rel: str) -> List[Dependency]:
    raw = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    raw_lines = raw.splitlines()
    deps: List[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version, pinned = _normalize_npm_version(spec)
            deps.append(Dependency("npm", name, version, pinned, rel,
                                   _find_line(raw_lines, f'"{name}"')))
    return deps


def _normalize_npm_version(spec: str):
    if not isinstance(spec, str):
        return None, False
    spec = spec.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+", spec):
        return spec, True
    m = re.match(r"[~^>=<\s]*(\d+\.\d+\.\d+)", spec)
    if m:
        return m.group(1), False  
    return None, False


def parse_package_lock(path: Path, rel: str) -> List[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    deps: List[Dependency] = []
    # lockfile v2/v3
    for pkg_path, info in (data.get("packages") or {}).items():
        if not pkg_path or not isinstance(info, dict):
            continue
        name = pkg_path.split("node_modules/")[-1]
        version = info.get("version")
        if name and version:
            deps.append(Dependency("npm", name, version, True, rel, 1))
    # lockfile v1
    for name, info in (data.get("dependencies") or {}).items():
        if isinstance(info, dict) and info.get("version"):
            deps.append(Dependency("npm", name, info["version"], True, rel, 1))
    return deps


def _find_line(raw_lines: List[str], needle: str) -> int:
    for i, line in enumerate(raw_lines, start=1):
        if needle in line:
            return i
    return 1


def collect_dependencies(root: Path) -> List[Dependency]:
    deps: List[Dependency] = []
    for path in find_manifests(root):
        rel = path.relative_to(root).as_posix()
        if path.name == "requirements.txt":
            deps.extend(parse_requirements(path, rel))
        elif path.name == "package.json":
            deps.extend(parse_package_json(path, rel))
        elif path.name == "package-lock.json":
            deps.extend(parse_package_lock(path, rel))
    return _dedupe(deps)


def _dedupe(deps: List[Dependency]) -> List[Dependency]:
    seen = set()
    out = []
    for d in deps:
        key = (d.ecosystem, d.name.lower(), d.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


# OSV lookup.

def query_osv(name: str, ecosystem: str, version: str) -> List[dict]:
    """Return OSV advisories affecting (name, version). [] on any failure."""
    payload = json.dumps({
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }).encode("utf-8")
    req = urllib.request.Request(OSV_QUERY_URL, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return [v for v in body.get("vulns", []) if not v.get("withdrawn")]
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError):
        return []


def _severity_from_osv(vuln: dict) -> str:
    sev = (vuln.get("database_specific", {}).get("severity") or "").upper()
    if sev in ("CRITICAL", "HIGH"):
        return HIGH
    if sev in ("MODERATE", "MEDIUM"):
        return MED
    if sev == "LOW":
        return LOW
    for entry in vuln.get("severity", []):
        score = entry.get("score", "")
        try:
            num = float(score)
        except (TypeError, ValueError):
            continue
        return HIGH if num >= 7 else MED if num >= 4 else LOW
    return MED  

def _first_fixed(vuln: dict) -> Optional[str]:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _display_id(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _cwe_from_osv(vuln: dict) -> Optional[str]:
    cwes = vuln.get("database_specific", {}).get("cwe_ids") or []
    return cwes[0] if cwes else None


# Top-level entry point.

def scan_dependencies(root: Path, offline: bool = False, jobs: Optional[int] = None) -> List[Finding]:
    findings: List[Finding] = []
    pinned: List[Dependency] = []
    for dep in collect_dependencies(root):
        if dep.version:
            pinned.append(dep)
        else:
            findings.append(Finding(
                rule="Unpinned Dependency",
                severity=LOW,
                category="Dependency",
                file=dep.file,
                line=dep.line,
                message=f"Dependency '{dep.name}' is unpinned; cannot verify against advisories",
                evidence=f"{dep.name} ({dep.ecosystem})",
                remediation="Pin an exact version or commit a lockfile so it can be vulnerability-scanned.",
                cwe="CWE-1104",
                confidence=0.4,
                language=ECOSYSTEM_LANGUAGE.get(dep.ecosystem),
            ))

    if offline or not pinned:
        return findings
    workers = jobs if (jobs and jobs > 0) else min(16, (os.cpu_count() or 4) + 4)
    workers = max(1, min(workers, len(pinned)))
    if workers <= 1:
        for dep in pinned:
            findings.extend(_lookup_dependency(dep))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(_lookup_dependency, pinned):
                findings.extend(result)
    return findings


def _lookup_dependency(dep: Dependency) -> List[Finding]:
    out: List[Finding] = []
    for vuln in query_osv(dep.name, dep.ecosystem, dep.version):
        fixed = _first_fixed(vuln)
        summary = vuln.get("summary") or (vuln.get("details") or "")[:120]
        remediation = (f"Upgrade {dep.name} to {fixed} or later."
                       if fixed else f"Upgrade {dep.name} to a non-vulnerable version.")
        out.append(Finding(
            rule="Vulnerable Dependency",
            severity=_severity_from_osv(vuln),
            category="Dependency",
            file=dep.file,
            line=dep.line,
            message=f"{dep.name} {dep.version} - {_display_id(vuln)}: {summary}".strip(),
            evidence=f"{dep.name}=={dep.version}",
            remediation=remediation,
            cwe=_cwe_from_osv(vuln),
            confidence=0.9 if dep.pinned else 0.55,
            language=ECOSYSTEM_LANGUAGE.get(dep.ecosystem),
        ))
    return out
