# Bootstrap the Mini Static Findings Scanner (Windows / PowerShell).
# Creates a virtual environment, installs pinned dependencies, and installs the
# `scanner` command. Run once, then activate the venv to use `scanner`.
#
# If script execution is blocked, run this once in your shell:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> Creating virtual environment in .venv ..."
python -m venv .venv

Write-Host "==> Upgrading pip ..."
& .\.venv\Scripts\python.exe -m pip install --upgrade pip | Out-Null

Write-Host "==> Installing pinned dependencies ..."
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "==> Installing the scanner (editable) ..."
& .\.venv\Scripts\python.exe -m pip install -e . --no-deps

Write-Host ""
Write-Host "Done. Use the scanner like this:"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "    scanner .\sample-project"
Write-Host ""
Write-Host "Or without activating:"
Write-Host "    .\.venv\Scripts\scanner.exe .\sample-project"
