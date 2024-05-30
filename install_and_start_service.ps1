$currentDir = split-path -parent $script:MyInvocation.MyCommand.Path

Set-Location -Path $currentDir | Out-Null

Write-Output "Install script file..."

$service_cmd = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ''{0}\powershell_browser_monitor.ps1''"' -f $currentDir 
"@echo off" | Out-File "$currentDir\start.bat" -Encoding Ascii
$service_cmd | Out-File -Append "$currentDir\start.bat" -Encoding Ascii

$scpath = 'C:\windows\system32\sc.exe'
$scarg = 'CREATE powershell_browser_monitor Displayname= "powershell_browser_monitor" binpath= "{0}" start= auto' -f "$currentDir\start.bat"
Write-Host $scarg

$scstart = 'start powershell_browser_monitor'
Start-Process -FilePath $scpath -ArgumentList $scarg -Wait -WindowStyle Hidden
Start-Process -FilePath $scpath -ArgumentList $scstart -WindowStyle Hidden

