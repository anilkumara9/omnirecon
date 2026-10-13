@echo off
REM OmniRecon one-command installer for Windows.
REM Creates .venv, installs deps, downloads Playwright Chromium, verifies.
REM Safe to re-run: completed steps are skipped.
setlocal enabledelayedexpansion

cd /d "%~dp0"
set VENV=.venv
set PY=%VENV%\Scripts\python.exe

echo [1/4] Checking Python...
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python 3.10+ not found. Install from https://www.python.org/downloads/
    echo Make sure to check "Add python.exe to PATH" during install.
    exit /b 1
)
python --version

echo [2/4] Creating virtualenv...
if not exist "%PY%" (
    python -m venv "%VENV%"
    if errorlevel 1 ( echo ERROR: venv creation failed. & exit /b 1 )
) else (
    echo already exists, skipping.
)

echo [3/4] Installing dependencies...
"%PY%" -m pip install --upgrade pip --quiet
"%PY%" -m pip install -r requirements.txt
if errorlevel 1 ( echo ERROR: pip install failed. & exit /b 1 )

echo [4/4] Installing Playwright Chromium (one-time, ~170MB)...
"%PY%" -m playwright install chromium
if errorlevel 1 (
    echo WARNING: Chromium install had issues. Browser tools need it;
    echo re-run "%PY% -m playwright install chromium" manually.
)

echo.
echo Verifying install...
"%PY%" -m omnirecon.cli --help >nul 2>&1
if errorlevel 1 ( echo ERROR: verification failed. & exit /b 1 )

echo.
echo Done. Next: configure your agent with zero path mistakes:
echo   %PY% -m omnirecon.cli setup cursor
echo   (or: claude-code, codex, windsurf, zed, generic)
echo Then ask your agent: "Reverse-engineer https://example.com"
endlocal
