#Scan orchestration: walk files, apply rules + validators, run SCA, rank.

import os
import re
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Iterable, List, Optional

from scanner import sca
from scanner.entropy import has_secret_context, shannon_entropy
from scanner.languages import detect_language
from scanner.rules import IGNORE_DIRS, RULES, TEXT_EXTENSIONS
from scanner.schema import SEVERITY_ORDER, Finding, Rule
from scanner.validators import MatchContext, evaluate, is_suppressed_inline

MAX_FILE_BYTES = 2_000_000  # skip files larger than 2MB 
MAX_LINE_LENGTH = 5_000     # cap line length fed to regexes 
PARALLEL_THRESHOLD = 2500   # only parallelize if we have at least this many files, to avoid process overhead on small scans


def scan_folder(
    root: Path,
    rules: Optional[List[Rule]] = None,
    min_confidence: float = 0.0,
    run_sca: bool = True,
    offline: bool = False,
    jobs: Optional[int] = None,
) -> List[Finding]:
    active_rules = [r for r in (rules if rules is not None else RULES) if r.enabled]
    files = list(iter_files(root))

    # Regex work is CPU-bound, so threads don't help, use processes instead.
    # Small trees stay sequential, since spawning processes costs more than it saves.
    workers = resolve_workers(jobs, len(files))
    if workers > 1 and len(files) >= PARALLEL_THRESHOLD:
        findings = _scan_parallel(root, files, active_rules, workers)
    else:
        findings = _scan_sequential(root, files, active_rules)

    if run_sca:
        findings.extend(sca.scan_dependencies(root, offline=offline, jobs=jobs))

    findings = dedupe(findings)
    findings = [f for f in findings if f.confidence >= min_confidence]
    return sort_findings(findings)


def resolve_workers(jobs: Optional[int], item_count: int) -> int:
    if jobs and jobs > 0:
        return jobs
    return os.cpu_count() or 4


def _scan_one(file_path: Path, root: Path, rules: List[Rule]) -> List[Finding]:
    rel_path = file_path.relative_to(root).as_posix()
    language = detect_language(file_path)
    result = scan_filename(file_path, rel_path, rules)
    if should_scan_content(file_path):
        result.extend(scan_file_content(file_path, rel_path, rules))
    for finding in result:
        finding.language = language
    return result


def _scan_sequential(root: Path, files: List[Path], rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for file_path in files:
        findings.extend(_scan_one(file_path, root, rules))
    return findings


# Set once per worker by the initializer so each task doesn't re-pickle these.
_WORKER_ROOT: Optional[Path] = None
_WORKER_RULES: Optional[List[Rule]] = None


def _init_worker(root_str: str, rules: List[Rule]) -> None:
    global _WORKER_ROOT, _WORKER_RULES
    _WORKER_ROOT = Path(root_str)
    _WORKER_RULES = rules


def _scan_file_task(file_path_str: str) -> List[Finding]:
    return _scan_one(Path(file_path_str), _WORKER_ROOT, _WORKER_RULES)


def _scan_parallel(root: Path, files: List[Path], rules: List[Rule], workers: int) -> List[Finding]:
    chunksize = max(1, len(files) // (workers * 8))
    try:
        with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                                 initargs=(str(root), rules)) as pool:
            findings: List[Finding] = []
            for result in pool.map(_scan_file_task, [str(f) for f in files], chunksize=chunksize):
                findings.extend(result)
            return findings
    except Exception:
        # Some environments block process pools, fall back to sequential.
        return _scan_sequential(root, files, rules)


def iter_files(root: Path) -> Iterable[Path]:
    # followlinks=False keeps us out of symlinked dirs.
    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune ignored directories in place so we never descend into them.
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if not _within_tree(path, root_resolved):
                continue  # symlinked file pointing outside the scanned tree
            yield path


def _within_tree(path: Path, root_resolved: Path) -> bool:
    """Allow regular files; for symlinks, require the target to stay inside root."""
    try:
        if not path.is_symlink():
            return True
        target = path.resolve()
        return target == root_resolved or root_resolved in target.parents
    except OSError:
        return False


def should_scan_content(file_path: Path) -> bool:
    is_text = file_path.suffix.lower() in TEXT_EXTENSIONS or file_path.name.startswith(".env")
    if not is_text:
        return False
    try:
        return file_path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def scan_filename(file_path: Path, rel_path: str, rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        if rule.detection_type != "filename":
            continue
        for pattern in rule.patterns:
            if re.search(pattern, rel_path, flags=re.IGNORECASE):
                findings.append(_finding(rule, rel_path, 1, file_path.name, rule.confidence_base))
                break
    return findings


def scan_file_content(file_path: Path, rel_path: str, rules: List[Rule]) -> List[Finding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    
    lines = [ln[:MAX_LINE_LENGTH] for ln in text.splitlines()]

    findings: List[Finding] = []
    for idx, line in enumerate(lines):
        if is_suppressed_inline(line):
            continue
        findings.extend(_scan_line_regex(rel_path, lines, idx, rules))
        findings.extend(_scan_line_entropy(rel_path, lines, idx, rules))
    return findings


def _scan_line_regex(rel_path: str, lines: List[str], idx: int, rules: List[Rule]) -> List[Finding]:
    line = lines[idx]
    out: List[Finding] = []
    for rule in rules:
        if rule.detection_type != "regex":
            continue
        if _has_negative_keyword(rule, line):
            continue
        match = _first_match(rule, line)
        if not match:
            continue
        if not _context_satisfied(rule, lines, idx):
            continue
        confidence = _confidence(rule, line, lines, idx, rel_path, match.group(0))
        if confidence is None:
            continue
        out.append(_finding(rule, rel_path, idx + 1, line.strip(), confidence))
    return out


def _scan_line_entropy(rel_path: str, lines: List[str], idx: int, rules: List[Rule]) -> List[Finding]:
    line = lines[idx]
    if not has_secret_context(line):
        return []
    out: List[Finding] = []
    for rule in rules:
        if rule.detection_type != "entropy_context":
            continue
        threshold = rule.entropy_threshold or 4.2
        candidate = _entropy_candidate(rule, line, threshold)
        if candidate is None:
            continue
        confidence = _confidence(rule, line, lines, idx, rel_path, candidate)
        if confidence is None:
            continue
        out.append(_finding(rule, rel_path, idx + 1, line.strip(), confidence))
    return out


def _first_match(rule: Rule, line: str):
    for pattern in rule.patterns:
        match = re.search(pattern, line)
        if match:
            return match
    return None


def _entropy_candidate(rule: Rule, line: str, threshold: float) -> Optional[str]:
    for pattern in rule.patterns:
        for match in re.finditer(pattern, line):
            candidate = match.group(0).strip("'\"")
            if shannon_entropy(candidate) >= threshold:
                return candidate
    return None


def _has_negative_keyword(rule: Rule, line: str) -> bool:
    if not rule.negative_keywords:
        return False
    lowered = line.lower()
    return any(kw.lower() in lowered for kw in rule.negative_keywords)


def _context_satisfied(rule: Rule, lines: List[str], idx: int) -> bool:
    if not rule.context_keywords:
        return True
    lo = max(0, idx - rule.context_window)
    hi = min(len(lines), idx + rule.context_window + 1)
    window = " ".join(lines[lo:hi])
    # Word-boundary match so things like "hash" does not match inside "hashlib".
    return any(re.search(rf"\b{re.escape(kw)}\b", window, re.IGNORECASE)
               for kw in rule.context_keywords)


def _confidence(rule: Rule, line: str, lines: List[str], idx: int, rel_path: str, match_text: str) -> Optional[float]:
    ctx = MatchContext(line=line, lines=lines, line_index=idx, rel_path=rel_path,
                       rule=rule, match_text=match_text)
    result = evaluate(ctx)
    if result.suppress:
        return None
    return max(0.0, min(1.0, rule.confidence_base + result.delta))


def _finding(rule: Rule, rel_path: str, line: int, evidence: str, confidence: float) -> Finding:
    return Finding(
        rule=rule.name,
        severity=rule.severity,
        category=rule.category,
        file=rel_path,
        line=line,
        message=rule.description,
        evidence=evidence[:200],
        remediation=rule.remediation,
        cwe=rule.cwe,
        confidence=round(confidence, 2),
    )


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Drop exact duplicates and collapse overlapping secret hits on one line."""
    best: dict = {}
    order: List[tuple] = []
    for f in findings:
        # All Secrets-category hits on the same line collapse to the strongest one.
        key = (f.file, f.line, "Secrets") if f.category == "Secrets" else (f.file, f.line, f.rule)
        if key not in best:
            best[key] = f
            order.append(key)
        elif f.confidence > best[key].confidence:
            best[key] = f
    return [best[k] for k in order]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence, f.file, f.line, f.rule),
    )
