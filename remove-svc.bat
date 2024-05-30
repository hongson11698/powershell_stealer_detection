@echo off

SET currentpath=%~dp0
cd /d %currentpath%

echo "removing powershell_browser_monitor service"

sc.exe delete powershell_browser_monitor

echo "Done!"
pause
