@echo off
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Project .venv not found. Follow docs\guia-instalacao.md first. 1>&2
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0scripts\update_bridge.py" %*
exit /b %errorlevel%
