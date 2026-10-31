@echo off
setlocal
"%~dp0runtime\node.exe" "%~dp0dist\index.js" %*
exit /b %ERRORLEVEL%
