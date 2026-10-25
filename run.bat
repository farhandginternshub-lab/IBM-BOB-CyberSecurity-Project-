@echo off
title Smart URL Reputation Checker
color 0B

echo.
echo  ============================================================
echo   Smart URL Reputation Checker
echo   Cybersecurity Project -- IBM SkillsBuild / BOB CS
echo  ============================================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo  [ERROR] Python is not installed or not on PATH.
    echo  Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Install dependencies silently if missing
echo  [1/2] Checking dependencies...
pip install flask requests tldextract --quiet --disable-pip-version-check

echo  [2/2] Starting server...
echo.
echo  Open your browser at: http://127.0.0.1:5000
echo  Press Ctrl+C in this window to stop the server.
echo.

python StudentName_SmartURLReputationChecker.py

pause
