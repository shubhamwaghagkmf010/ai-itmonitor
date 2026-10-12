@echo off
setlocal EnableDelayedExpansion
title AI-ITMonitor Agent

REM --- Require administrator (needed for service control / reboot) ---
net session >nul 2>&1
if %errorLevel% neq 0 (
  echo [*] Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "SERVER_URL=__SERVER_URL__"
set "INVENTORY_INTERVAL=1800"
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

echo [*] Starting AI-ITMonitor agent...
%PY% "%~dp0agent/main.py"
echo.
echo [*] Agent stopped.
pause
exit /b

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
