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
        [string]$AccessSent
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

$filemonRegex = '(?i).*\\Appdata\\.*(Chrome|Firefox|Edge|Opera|Coccoc|Brave).*(key4\.db|logins\.json|User Data.*\\Local State|User Data.*\\Login Data|Opera.*\\Login Data)$'# 
Write-Output "Begin Browser audit setting..."# 
$UsersDir = "$Env:SystemDrive\Users"# 
$browserSensitiveFile = Get-ChildItem -Force -Recurse $UsersDir -ErrorAction SilentlyContinue | Where-Object {!$_.PSIsContainer } | Select-Object "FullName" | Where-Object {$_.FullName -match $filemonRegex}# 
foreach ($file in $browserSensitiveFile) {
    if ($file -eq "") {
        continue
    }
    $log = "Enable audit for {0}" -f $file.FullName
    Write-Output $log
    Set-Audit-FileSystem $file.FullName "Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions"
}
Write-Output "Browser audit setting Done"