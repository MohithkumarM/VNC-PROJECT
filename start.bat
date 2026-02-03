@echo off
title VNC Security Monitor
color 0A

echo.
echo =====================================================
echo         VNC SECURITY MONITOR - STARTUP
echo =====================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Check for virtual environment
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
)

REM Install requirements if needed
if not exist "requirements_installed.flag" (
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    echo. > requirements_installed.flag
)

echo.
echo [INFO] Starting VNC Security Monitor...
echo.

REM Run the application
python run.py --debug

pause
