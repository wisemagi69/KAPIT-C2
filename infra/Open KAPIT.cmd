@echo off
setlocal
python "%~dp0open_local.py" %*
if errorlevel 1 (
  echo.
  echo The website could not be opened. Review the diagnostic above, then try again.
  pause
  exit /b 1
)
endlocal
