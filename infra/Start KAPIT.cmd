@echo off
setlocal
cd /d "%~dp0.."
echo Starting the complete local KAPIT-C2 application.
echo Keep this window open while using the workspace.
echo Setup verifies dependencies and the database before creating local accounts.
echo.
python -B infra\start_local.py
set "KAPIT_START_EXIT=%ERRORLEVEL%"
if not "%KAPIT_START_EXIT%"=="0" (
  echo.
  echo KAPIT-C2 setup stopped. Login is unavailable until setup completes.
  echo The error above identifies the failed step. Existing data is retained.
)
echo.
pause
exit /b %KAPIT_START_EXIT%
