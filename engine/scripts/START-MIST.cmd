@echo off
setlocal
cd /d "%~dp0"

:: MIST needs Administrator rights to create the TUN interface and routes.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Requesting Administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

if not exist "mist-client-windows-amd64.exe" (
  echo [ERROR] mist-client-windows-amd64.exe is missing from this folder.
  echo Re-extract the complete MIST-Windows-Portable archive.
  pause
  exit /b 2
)

if not exist "client.json" (
  echo [ERROR] client.json is missing.
  echo Copy client.json from your previous working MIST build into this folder.
  echo The packaged client.example.json is documentation only and must not be used as a live config.
  pause
  exit /b 3
)

findstr /I /C:"edge-a.example.com" /C:"edge-b.example.net" /C:"203.0.113." /C:"198.51.100." /C:"REPLACE_WITH" "client.json" >nul 2>&1
if "%errorlevel%"=="0" (
  echo [ERROR] client.json is still the example configuration.
  echo It contains documentation-only addresses and cannot connect to a real MIST server.
  echo.
  echo Replace this file with client.json from your previous working MIST build.
  echo Do NOT run client.example.json as a live configuration.
  pause
  exit /b 4
)

echo ================================================
echo   MIST hardening-32 - AUTO transport
echo ================================================
echo Config: %CD%\client.json
echo Press Ctrl+C to stop MIST.
echo.

"%CD%\mist-client-windows-amd64.exe" -config "%CD%\client.json" -transport auto
set "code=%errorlevel%"

echo.
echo ================================================
echo MIST stopped. Exit code: %code%
echo If this was unexpected, copy the error text above.
echo ================================================
pause
exit /b %code%
