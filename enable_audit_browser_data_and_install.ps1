function Set-Audit-FileSystem {
    <#
    .SYNOPSIS
    #  This is based on the 'Windows File Auditing Cheat Sheet'
    #  www.MalwareArchaeology.com\cheat-sheets
    #
    Set File or Dir Auditing for Everyone

    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$path,
        [string]$AccessSent,
        [string]$KeyAndSubs
    )
    try {
        if (Test-Path -LiteralPath $path) {
            $ACL = new-object System.Security.AccessControl.DirectorySecurity
            $AccessRule = new-object System.Security.AccessControl.FileSystemAuditRule("Everyone", $AccessSent, "ContainerInherit, ObjectInherit", "NoPropagateInherit", "Success")
            $ACL.SetAuditRule($AccessRule)
            $ACL | Set-Acl $path
            Write-Output "Set-Audit-FileSystem  OKAY: $path"
        }
        else {
            Write-Output "Set-Audit-FileSystem Error: $path not found"
        }
    }
    catch {
        Write-Output "Set-Audit-FileSystem Error: $path"
    }
}


$currentDir = (Get-Item .).FullName

Set-Location -Path $currentDir | Out-Null

Write-Output "Install script file..."

$service_cmd = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ''{0}\powershel_browser_monitor.ps1''"' -f $currentDir 
"@echo off" | Out-File "$currentDir\start.bat" -Encoding Ascii
$service_cmd | Out-File -Append "$currentDir\start.bat" -Encoding Ascii

$scpath = 'C:\windows\system32\sc.exe'
$scarg = 'CREATE powershel_browser_monitor Displayname= "powershel_browser_monitor" binpath= "{0}" start= auto' -f "$currentDir\start.bat"
Write-Host $scarg

$scstart = 'start powershel_browser_monitor'
Start-Process -FilePath $scpath -ArgumentList $scarg -Wait -WindowStyle Hidden
Start-Process -FilePath $scpath -ArgumentList $scstart -WindowStyle Hidden

$filemonRegex = '(?i).*\\Appdata\\.*(Chrome|Firefox|Edge|Opera|Coccoc|Brave).*(key4\.db|logins\.json|User Data.*\\Local State|User Data.*\\Login Data|Opera.*\\Login Data)$'# 
Write-Output "Begin Browser audit setting..."# 
$UsersDir = "$Env:SystemDrive\Users"# 
$browserSensitiveFile = Get-ChildItem -Force -Attributes !Directory -Recurse $UsersDir -ErrorAction SilentlyContinue | Select-Object "FullName" | Where-Object {$_.FullName -match $filemonRegex}# 
foreach ($file in $browserSensitiveFile) {
    $log = "Enable audit for {0}" -f $file.FullName
    Write-Output $log
    Set-Audit-FileSystem $file.FullName "Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions"# 
}
Write-Output "Browser audit setting Done"


