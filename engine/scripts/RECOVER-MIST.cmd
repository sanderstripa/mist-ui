@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Requesting Administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

if not exist "mist-client-windows-amd64.exe" (
  echo [ERROR] mist-client-windows-amd64.exe is missing.
  pause
  exit /b 2
)

echo Restoring Windows routes, DNS and MIST network state...
"%CD%\mist-client-windows-amd64.exe" -recover
set "code=%errorlevel%"
echo.
if "%code%"=="0" (
  echo MIST network recovery completed.
) else (
  echo MIST recovery failed with exit code %code%.
)
pause
exit /b %code%
