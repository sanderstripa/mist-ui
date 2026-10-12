@echo off
setlocal EnableExtensions
chcp 65001 >nul
title MIST Edge Update
cd /d "%~dp0"

set "PAYLOAD=%~dp0MIST-EDGE-PAYLOAD.tar.gz"
set "HOST_FILE=%~dp0MIST-SERVER.txt"

if not exist "%PAYLOAD%" (
  echo [ERROR] MIST-EDGE-PAYLOAD.tar.gz not found.
  pause
  exit /b 2
)

where ssh.exe >nul 2>&1 || (
  echo [ERROR] Windows OpenSSH Client is not installed.
  pause
  exit /b 3
)

set "MIST_HOST="
if exist "%HOST_FILE%" set /p MIST_HOST=<"%HOST_FILE%"
if not defined MIST_HOST (
  set /p "MIST_HOST=Server IP or hostname: "
  if not defined MIST_HOST exit /b 4
  >"%HOST_FILE%" echo %MIST_HOST%
)

echo.
echo MIST Edge update for root@%MIST_HOST%
echo Enter the server SSH password when Windows asks for it.
echo Existing server.json, certificates and tokens will be preserved.
echo.

ssh.exe -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "root@%MIST_HOST%" "rm -rf /tmp/mist-edge-update /tmp/mist-edge-update.tar.gz; mkdir -p /tmp/mist-edge-update; cat > /tmp/mist-edge-update.tar.gz; tar -xzf /tmp/mist-edge-update.tar.gz -C /tmp/mist-edge-update --strip-components=1 || exit 20; chmod +x /tmp/mist-edge-update/UPDATE-MIST-EDGE.sh /tmp/mist-edge-update/verify-edge.sh; sh -n /tmp/mist-edge-update/UPDATE-MIST-EDGE.sh || exit 21; sh /tmp/mist-edge-update/UPDATE-MIST-EDGE.sh; RC=$?; rm -rf /tmp/mist-edge-update /tmp/mist-edge-update.tar.gz; exit $RC" < "%PAYLOAD%"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo [OK] MIST Edge updated successfully.
) else (
  echo [ERROR] MIST Edge update failed. Code: %RC%
  echo The server-side updater keeps a backup and rolls back if the new Edge does not start.
)
echo.
pause
exit /b %RC%
