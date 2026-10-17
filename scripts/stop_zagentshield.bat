@echo off
setlocal EnableExtensions
cd /d "%~dp0.."

echo ================================================================
echo  Z-AgentShield safe shutdown
echo ================================================================
echo This script does not kill processes by port, executable name, or window title.
echo.
echo In the two titled terminals opened by run_zagentshield.bat:
echo   1. Select the Gateway terminal and press Ctrl+C.
echo   2. Select the Dashboard terminal and press Ctrl+C.
echo.
set /p "STOPPED=Have both Z-AgentShield server terminals stopped? (Y/N): "
if /i not "%STOPPED%"=="Y" (
    echo [INFO] Nothing was terminated or removed.
    exit /b 0
)

if not exist "scripts\.local_db_path" (
    echo [INFO] No isolated-run database path was recorded.
    echo Services may have been started manually; stop them with Ctrl+C.
    exit /b 0
)

set /p "DATABASE_PATH="<"scripts\.local_db_path"
if not defined DATABASE_PATH (
    echo [WARN] The recorded database path is empty; leaving files untouched.
    exit /b 1
)
echo %DATABASE_PATH% | findstr /I /B /L /C:"%TEMP%\Z-AgentShield-Local-" >nul
if errorlevel 1 (
    echo [WARN] The recorded path is not under the expected temporary directory.
    echo        No files were removed: %DATABASE_PATH%
    exit /b 1
)
if /i not "%DATABASE_PATH:~-3%"==".db" (
    echo [WARN] The recorded file does not have the expected .db suffix.
    echo        No files were removed.
    exit /b 1
)

set "PID_8000="
set "PID_8501="
for /f "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /R /C:":8000 .*LISTENING" 2^>nul') do set "PID_8000=%%P"
for /f "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /R /C:":8501 .*LISTENING" 2^>nul') do set "PID_8501=%%P"
if defined PID_8000 (
    echo [WARN] Port 8000 still has a listener (PID !PID_8000!); database cleanup skipped.
    echo        The listener is not terminated.
    exit /b 1
)
if defined PID_8501 (
    echo [WARN] Port 8501 still has a listener (PID !PID_8501!); database cleanup skipped.
    echo        The listener is not terminated.
    exit /b 1
)

echo [INFO] Removing the exact isolated database and SQLite sidecar paths:
echo        %DATABASE_PATH%
if exist "%DATABASE_PATH%" del /q "%DATABASE_PATH%"
if exist "%DATABASE_PATH%-wal" del /q "%DATABASE_PATH%-wal"
if exist "%DATABASE_PATH%-shm" del /q "%DATABASE_PATH%-shm"
if exist "scripts\.local_db_path" del /q "scripts\.local_db_path"
echo [OK] Isolated run data cleanup complete.
echo No unrelated process was stopped.
