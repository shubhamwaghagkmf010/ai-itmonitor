@echo off
setlocal EnableDelayedExpansion
title AI-ITMonitor Agent

REM --- Require administrator (needed to install into Program Files, create the
REM     scheduled task, kill process trees, control services, reboot) ---
net session >nul 2>&1
if %errorLevel% neq 0 (
  echo [*] Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "SERVER_URL=__SERVER_URL__"
set "INVENTORY_INTERVAL=1800"
set "INSTALL_DIR=%ProgramFiles%\AI-ITMonitor"

REM --- If we are NOT already running from the protected install dir, install there
REM     first and hand off to the installed copy. This makes the download/extract
REM     folder disposable - deleting it never breaks the agent or its auto-start. ---
if /I "%~dp0"=="%INSTALL_DIR%\" goto installed

echo [*] Installing AI-ITMonitor agent into "%INSTALL_DIR%" ^(protected location^)...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
xcopy /e /i /y "%~dp0agent" "%INSTALL_DIR%\agent" >nul
copy /y "%~f0" "%INSTALL_DIR%\run.bat" >nul

REM Lock it down so only SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) can
REM modify the agent; standard Users (S-1-5-32-545) get read+execute only. This
REM stops a normal user or user-level malware from tampering with the agent.
icacls "%INSTALL_DIR%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" >nul 2>&1

echo [*] Registering auto-start task "AIITMonitorAgent" ^(points to the installed copy^)...
schtasks /create /tn "AIITMonitorAgent" /tr "\"%INSTALL_DIR%\run.bat\"" /sc onstart /ru SYSTEM /rl highest /f >nul 2>&1
if !errorLevel! equ 0 (
  echo [*] Auto-start installed - the agent will start automatically after every reboot.
) else (
  echo [!] Could not register the auto-start task ^(continuing anyway^).
)

echo [*] Install complete. Launching the installed agent...
start "" "%INSTALL_DIR%\run.bat"
echo [*] You may now close this window and delete the downloaded folder.
exit /b

:installed
set "PYTHONPATH=%~dp0"

REM --- Find a working Python interpreter ---
call :find_python
if defined PY goto have_python

echo.
echo [*] Python was not found on this machine. Installing Python 3 ^(one-time, this may take a few minutes^)...
echo.

REM --- Attempt 1: winget (if present) ---
where winget >nul 2>&1
if %errorLevel% equ 0 (
  echo [*] Installing via winget...
  winget install -e --id Python.Python.3.12 --scope machine --accept-package-agreements --accept-source-agreements --disable-interactivity
  call :find_python
  if defined PY goto have_python
  echo [*] winget install did not provide Python - falling back to the official installer...
) else (
  echo [*] winget not available - using the official installer...
)

REM --- Attempt 2: download the official installer with PowerShell (always works) ---
echo [*] Downloading the official Python installer...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $u='https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe'; $o=Join-Path $env:TEMP 'python-setup.exe'; Invoke-WebRequest -Uri $u -OutFile $o; Write-Host '[*] Installing Python (silent)...'; $p=Start-Process -Wait -PassThru -FilePath $o -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1'; exit $p.ExitCode"

REM --- Re-detect Python after install (current session PATH may be stale) ---
call :find_python
if defined PY goto have_python

echo.
echo [!] Python could not be installed automatically.
echo     Please install Python 3 from https://www.python.org/downloads/
echo     ^(tick "Add python.exe to PATH" during setup^), then run this file again.
echo.
pause
exit /b 1

:have_python
echo [*] Using Python: %PY%
%PY% --version

echo [*] Installing / updating agent dependencies ^(httpx, psutil^)...
%PY% -m pip install --quiet --upgrade pip >nul 2>&1
%PY% -m pip install --quiet --upgrade httpx psutil
if %errorLevel% neq 0 (
  echo [!] Dependency installation failed. Check your internet connection and try again.
  pause
  exit /b 1
)

REM --- Self-heal: make sure the auto-start task still exists and points here ---
schtasks /query /tn "AIITMonitorAgent" >nul 2>&1
if %errorLevel% neq 0 (
  schtasks /create /tn "AIITMonitorAgent" /tr "\"%~f0\"" /sc onstart /ru SYSTEM /rl highest /f >nul 2>&1
)

REM ============================================================
REM  Supervisor loop: run the agent, apply staged updates, and
REM  restart on exit/crash. Exit code 42 = "update staged".
REM ============================================================
:run_loop
echo.
echo [*] Starting AI-ITMonitor agent...
%PY% "%~dp0agent\main.py"
set "RC=%errorLevel%"

if "%RC%"=="42" (
  echo [*] An update was downloaded - applying...
  if exist "%~dp0_staging\agent" (
    xcopy /e /i /y "%~dp0_staging\agent" "%~dp0agent" >nul
    rmdir /s /q "%~dp0_staging" >nul 2>&1
    echo [*] Update applied. Restarting the agent...
  ) else (
    echo [!] Update folder not found - restarting on the current version.
  )
  goto run_loop
)

echo [*] Agent exited (code %RC%). Restarting in 10 seconds...  (close this window to stop)
timeout /t 10 /nobreak >nul
goto run_loop

REM ============================================================
REM  find_python: sets PY to a working interpreter, or leaves it unset
REM ============================================================
:find_python
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3" && goto :eof
python --version >nul 2>&1 && set "PY=python" && goto :eof
python3 --version >nul 2>&1 && set "PY=python3" && goto :eof
if exist "%SystemRoot%\py.exe" ( "%SystemRoot%\py.exe" -3 --version >nul 2>&1 && set "PY=%SystemRoot%\py.exe -3" && goto :eof )
for %%D in ("%ProgramFiles%\Python3*" "%ProgramFiles(x86)%\Python3*" "%LocalAppData%\Programs\Python\Python3*") do (
  if exist "%%~D\python.exe" set "PY=%%~D\python.exe"
)
goto :eof
