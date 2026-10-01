param(
    [string]$Python = "py"
)

$ErrorActionPreference = "Stop"

& $Python -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[test,windows]"
& .\.venv\Scripts\python.exe -m pytest -q
Write-Host "DroidShield Windows build environment is ready."
Write-Host "Run: .\.venv\Scripts\droidshield.exe windows"
Write-Host "Run: .\.venv\Scripts\droidshield.exe gui"
