@echo off
setlocal
cd /d "%~dp0.."
echo Reading finite local PostgreSQL diagnostics. Existing data is retained.
python -B infra\local.py native-diagnose
set "KAPIT_DIAG_EXIT=%ERRORLEVEL%"
echo.
echo Diagnostics do not verify login or establish the earlier startup cause.
pause
exit /b %KAPIT_DIAG_EXIT%
