@echo off
REM Double-click launcher for AutoASM-NG on Windows.
REM Starts the web app at http://127.0.0.1:5000 and opens your browser.
title AutoASM-NG
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py run_local.py
) else (
    python run_local.py
)

echo.
echo AutoASM-NG has stopped. Press any key to close this window.
pause >nul
