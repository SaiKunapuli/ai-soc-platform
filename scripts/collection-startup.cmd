@echo off
REM =====================================================================
REM  SOC data-collection startup check + auto-fix.
REM  Double-click this after your machine boots. It self-elevates (the
REM  agent-service restart needs admin), then runs restore-collection.ps1:
REM    - starts Docker Desktop if the engine is down
REM    - waits for the Wazuh containers + indexer
REM    - if the agent is stuck, breaks the enrollment deadlock
REM    - verifies events are flowing again
REM  Safe to run when everything is already healthy (it just verifies).
REM =====================================================================

REM --- self-elevate if not already admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

echo ============================================================
echo   SOC COLLECTION STARTUP CHECK
echo ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0restore-collection.ps1"
echo ============================================================
echo   Done. Review the status line above.
echo ============================================================
pause
