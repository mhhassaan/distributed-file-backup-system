@echo off
SETLOCAL EnableDelayedExpansion
TITLE Main Control Script

:: Check if the user provided the number of nodes to start
if "%1"=="" (
    ECHO ERROR: Please specify the number of storage nodes to start.
    ECHO Usage: start_all.bat 4
    pause
    exit /b
)

SET num_nodes=%1

ECHO.
ECHO ==================================================
ECHO   Starting Distributed Backup System
ECHO   (Coordinator, Web UI, and %num_nodes% Storage Nodes)
ECHO ==================================================
ECHO.

ECHO Activating Python virtual environment...
:: Make sure this path is correct (e.g., venv or dbms)
CALL .\dbms\Scripts\activate

ECHO Starting all servers in separate windows. Please wait...
ECHO.

:: Start the Coordinator Server (static)
ECHO [+] Starting Coordinator on port 5002...
start "Coordinator (Port 5002)" cmd /c "python coordinator.py & pause"
timeout /t 2 > NUL

:: Start the Web UI Server (static)
ECHO [+] Starting Web UI on port 5000...
start "Web UI Client (Port 5000)" cmd /c "python web_ui.py & pause"
timeout /t 2 > NUL

:: Loop and start the specified number of Storage Nodes
ECHO [+] Starting %num_nodes% Dropbox Storage Nodes...
FOR /L %%i IN (1, 1, %num_nodes%) DO (
    SET /A port=5010 + %%i
    SET node_id=node%%i
    ECHO    - Starting Dropbox Node %%i on port !port!...
    start "Dropbox Node %%i (Port !port!)" cmd /c "python storage_node_dropbox.py !port! !node_id! & pause"
    timeout /t 1 > NUL
)

ECHO.
ECHO All components have been launched.