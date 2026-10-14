@echo off
REM MailGuard backend - local run on Windows (double-click, or run .\run_local.cmd from PowerShell).
REM First run creates the Python environment and installs the libraries; later runs just start.
REM The shared secret is read from backend\.env (MG_HMAC_SECRET=...), see .env.example.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating the Python environment ^(first run only^)...
  py -V:Astral\CPython3.14.4 -m venv .venv 2>nul || py -3.14 -m venv .venv 2>nul || py -3.13 -m venv .venv 2>nul || py -3.12 -m venv .venv
  if not exist ".venv\Scripts\python.exe" (
    echo Could not create the environment. Install Python 3.12-3.14 from python.org and try again.
    pause
    exit /b 1
  )
  ".venv\Scripts\python" -m pip install -r requirements.txt
)
if not exist ".env" echo WARNING: backend\.env is missing - answers will not be signed and the add-on will reject them.
".venv\Scripts\python" -m uvicorn app.main:app --port 8080
pause
