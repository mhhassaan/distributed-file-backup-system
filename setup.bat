@echo off
TITLE Project Setup Script

ECHO.
ECHO ===============================================
ECHO   Setting up the Distributed Backup System
ECHO ===============================================
ECHO.

ECHO Checking for Python...
python --version > NUL 2>&1
if %errorlevel% neq 0 (
    ECHO ERROR: Python is not installed or not found in your PATH.
    ECHO Please install Python 3 and try again.
    pause
    exit /b
)

ECHO [1/3] Creating a new Python virtual environment named 'venv'...
python -m venv venv

ECHO.
ECHO [2/3] Activating the virtual environment...
CALL .\venv\Scripts\activate

ECHO.
ECHO [3/3] Installing all required project libraries from requirements.txt...
pip install -r requirements.txt

ECHO.
ECHO ===============================================
ECHO   Setup Complete!
ECHO ===============================================
ECHO You can now run the system using the 'start_all.bat' script.
ECHO.
pause