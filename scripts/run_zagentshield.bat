@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0.."
if errorlevel 1 (
    echo [ERROR] Could not change to the project root.
    exit /b 1
)

echo ================================================================
echo  Z-AgentShield local runner
echo ================================================================
echo Project: %CD%

set "PYTHON_EXE="
if defined ZAGENTSHIELD_PYTHON set "PYTHON_EXE=%ZAGENTSHIELD_PYTHON%"
if not defined PYTHON_EXE if exist "%CD%\.venv\Scripts\python.exe" set "PYTHON_EXE=%CD%\.venv\Scripts\python.exe"
if not defined PYTHON_EXE (
    for /f "delims=" %%P in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
)
if not defined PYTHON_EXE (
    echo [ERROR] Python was not found.
    echo Set ZAGENTSHIELD_PYTHON to an installed Python executable or create .venv.
    exit /b 1
)
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Python executable does not exist: %PYTHON_EXE%
    echo Set ZAGENTSHIELD_PYTHON to an installed Python executable.
    exit /b 1
)

echo Python: %PYTHON_EXE%
"%PYTHON_EXE%" --version
if errorlevel 1 (
    echo [ERROR] The selected Python executable could not run.
    exit /b 1
)

echo [INFO] Checking required packages...
"%PYTHON_EXE%" -c "import fastapi, uvicorn, streamlit, pydantic, pydantic_settings, yaml, sklearn, pandas, numpy, requests" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] One or more required packages are missing from this Python environment.
    echo Install the project dependencies into this environment with:
    echo   "%PYTHON_EXE%" -m pip install -r requirements.txt
    exit /b 1
)

if not exist "config\policies.yaml" (
    echo [ERROR] Missing config\policies.yaml. Run this script from the complete project checkout.
    exit /b 1
)

set "PID_8000="
set "PID_8501="
for /f "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /R /C:":8000 .*LISTENING" 2^>nul') do set "PID_8000=%%P"
for /f "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /R /C:":8501 .*LISTENING" 2^>nul') do set "PID_8501=%%P"
if defined PID_8000 (
    echo [ERROR] Port 8000 is already occupied by PID !PID_8000!.
    echo No process was started or stopped. Identify the listener and free the port, then retry.
    exit /b 2
)
if defined PID_8501 (
    echo [ERROR] Port 8501 is already occupied by PID !PID_8501!.
    echo No process was started or stopped. Identify the listener and free the port, then retry.
    exit /b 2
)

set "PYTHONPATH=%CD%\src"
set "HOST=127.0.0.1"
set "PORT=8000"
set "DASHBOARD_HOST=127.0.0.1"
set "DASHBOARD_PORT=8501"
set "APP_ENV=development"
set "POLICY_CONFIG_PATH=%CD%\config\policies.yaml"
set "DATABASE_PATH=%TEMP%\Z-AgentShield-Local-%RANDOM%-%RANDOM%.db"
if exist "%DATABASE_PATH%" (
    set "DATABASE_PATH=%TEMP%\Z-AgentShield-Local-%RANDOM%-%RANDOM%-%RANDOM%.db"
)
> "scripts\.local_db_path" echo %DATABASE_PATH%

echo [INFO] Using isolated local database: %DATABASE_PATH%
echo [INFO] Starting FastAPI at 127.0.0.1:8000 in a separate terminal...
start "Z-AgentShield Gateway" cmd /k ""%PYTHON_EXE%" -m uvicorn zagentshield.api.app:app --host 127.0.0.1 --port 8000"

echo [INFO] Waiting up to 45 seconds for the gateway identity and health checks...
set "API_READY=0"
for /l %%I in (1,1,45) do (
    "%PYTHON_EXE%" -c "import json,urllib.request; root=json.load(urllib.request.urlopen('http://127.0.0.1:8000/',timeout=1)); health=json.load(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=1)); raise SystemExit(0 if root.get('service')=='Z-AgentShield Security Gateway' and health.get('status')=='ok' else 1)" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "API_READY=1"
        goto :API_CHECKED
    )
    timeout /t 1 /nobreak >nul
)

:API_CHECKED
if "!API_READY!" neq "1" (
    echo [ERROR] Gateway did not identify itself as Z-AgentShield and pass /health.
    echo It is NOT reported as ONLINE. Inspect the Gateway terminal for errors.
    echo Stop that terminal with Ctrl+C before retrying.
    goto :OPEN_URLS
)
echo [OK] FastAPI Gateway is ONLINE; identity and health checks passed.

echo [INFO] Starting Streamlit at 127.0.0.1:8501 in a separate terminal...
start "Z-AgentShield Dashboard" cmd /k ""%PYTHON_EXE%" -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true"

echo [INFO] Waiting up to 45 seconds for the dashboard health endpoint...
set "DASHBOARD_READY=0"
for /l %%I in (1,1,45) do (
    "%PYTHON_EXE%" -c "import urllib.request; response=urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health',timeout=1); raise SystemExit(0 if response.status==200 else 1)" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "DASHBOARD_READY=1"
        goto :DASHBOARD_CHECKED
    )
    timeout /t 1 /nobreak >nul
)

:DASHBOARD_CHECKED
if "!DASHBOARD_READY!" equ "1" (
    echo [OK] Streamlit dashboard health endpoint responded.
) else (
    echo [ERROR] Dashboard did not respond at /_stcore/health.
    echo It is NOT reported as ONLINE. Inspect the Dashboard terminal for errors.
)

:OPEN_URLS
echo.
echo [INFO] Opening the requested local URLs in the default browser...
start "" "http://localhost:8501"
start "" "http://127.0.0.1:8000/docs"
start "" "http://127.0.0.1:8000/health"
start "" "http://127.0.0.1:8000/"
echo.
echo Dashboard:  http://localhost:8501
echo Swagger UI: http://127.0.0.1:8000/docs
echo API health: http://127.0.0.1:8000/health
echo API root:   http://127.0.0.1:8000/
echo Verify:     "%PYTHON_EXE%" scripts\verify_zagentshield.py
echo Stop:       scripts\stop_zagentshield.bat
echo.
echo Stop servers with Ctrl+C in both titled terminal windows.
echo A temporary isolated database is used for this run.
if "!API_READY!" neq "1" exit /b 1
if "!DASHBOARD_READY!" neq "1" exit /b 1
exit /b 0
