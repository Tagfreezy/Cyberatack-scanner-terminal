@echo off
rem CyberWatch dashboard launcher (Windows). Double-click or run from a terminal.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo First run: setting up the Python environment, this takes a minute...
  python -m venv .venv || goto :error
  ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt || goto :error
)
if not exist ".env" (
  echo Missing .env: copy .env.example to .env and fill in your API URL and token.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m cyberwatch_tui
exit /b %errorlevel%
:error
echo Setup failed. Is Python 3.11+ installed and on PATH?
pause
exit /b 1
