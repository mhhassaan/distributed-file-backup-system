@echo off
TITLE Stop All Servers

ECHO.
ECHO ==================================================
ECHO   Shutting Down Distributed File Backup System
ECHO ==================================================
ECHO.

ECHO [1/4] Stopping Web UI Client...
taskkill /F /FI "WINDOWTITLE eq Web UI Client (Port 5000)" > NUL

ECHO [2/4] Stopping Coordinator Server...
taskkill /F /FI "WINDOWTITLE eq Coordinator (Port 5002)" > NUL

ECHO [3/4] Stopping Storage Node 1...
taskkill /F /FI "WINDOWTITLE eq Storage Node 1 (Port 5001)" > NUL

ECHO [4/4] Stopping Storage Node 2...
taskkill /F /FI "WINDOWTITLE eq Storage Node 2 (Port 5003)" > NUL

ECHO.
ECHO All server processes have been terminated.
ECHO.
pause