@echo off

SET currentpath=%~dp0
cd /d %currentpath%

echo "Force Advance Audit Policy"
reg.exe add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
::
:: SET THE LOG SIZE -
echo "SET THE LOG SIZE Security"
wevtutil.exe sl Security /ms:524288000

echo "Audit File System"
Auditpol.exe /set /subcategory:"File System" /success:enable /failure:disable

echo "Setting audit Monitor browser sensitive data..."
@powershell "exit $PSVersionTable.PSVersion.Major"
if %errorlevel% GEQ 3 (
    echo "Powershell 3 detected! Unblocking file..."
    @powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File '%currentpath%*.ps1'"
)

@powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%currentpath%enable_audit_browser_data.ps1'"
@powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%currentpath%install_and_start_service.ps1'"

pause
