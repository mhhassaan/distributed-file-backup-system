@echo off
TITLE Main Control Script for Distributed Backup System

ECHO.
ECHO ===============================================
ECHO   Starting Distributed File Backup System
ECHO ===============================================
ECHO.

ECHO Activating Python virtual environment...
CALL .\dbms\Scripts\activate

ECHO Starting all servers in separate windows. Please wait...
ECHO.

:: Start the Coordinator Server first, as other components depend on it.
ECHO [1/4] Starting Coordinator on port 5002...
start "Coordinator (Port 5002)" python coordinator.py

:: Wait for a couple of seconds to let the server initialize before starting the nodes.
timeout /t 2 > NUL

:: Start the Storage Nodes
ECHO [2/4] Starting Storage Node 1 on port 5001...
start "Storage Node 1 (Port 5001)" python storage_node.py 5001

timeout /t 1 > NUL

ECHO [3/4] Starting Storage Node 2 on port 5003...
start "Storage Node 2 (Port 5003)" python storage_node.py 5003

:: Wait for a couple of seconds before starting the UI
timeout /t 2 > NUL

:: Start the Web UI Server
ECHO [4/4] Starting Web UI on port 5000...
start "Web UI Client (Port 5000)" python web_ui.py

ECHO.
ECHO All components have been launched in new windows.
ECHO This script will now close. To stop the system, close each window individually.
ECHO.