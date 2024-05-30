function Write-Log-To-File {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [string]$LogText
    )
    $LogText | Out-File $LogFile -Append
    return $LogText
} 

$scriptPath = split-path -parent $script:MyInvocation.MyCommand.Path

# Check Audit setting for supported browsers

. "$scriptPath\enable_audit_browser_data.ps1"

$ErrorLogFile = "C:\powershell_browser_monitor_errorlog.txt" 

$MainLogFile = "C:\powershell_browser_monitor.txt" 

$nowTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")

$null = Write-Log-To-File $MainLogFile "`n$nowTime -- New Session Start ($PID) -------------------`n"

$processAlowRegex   = '(?i)^((c:\\windows\\system32\\svchost|c:\\windows\\explorer|(c:\\program files\\.*|c:\\program files \(x86\)\\.*|c:\\Users\\.*\\appdata\\Local\\.*)(browser|firefox|chrome|edge|opera|coccoc|brave)))\.exe$'
$filemonRegex = '(?i).*\\Appdata\\.*(Chrome|Firefox|Edge|Opera|Coccoc|Brave).*(key4\.db|logins\.json|User Data.*\\Local State|User Data.*\\Login Data|Opera.*\\Login Data)$'# 

Register-WmiEvent -Query "Select * From __InstanceCreationEvent Where TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Security' AND (TargetInstance.EventCode=4663 OR TargetInstance.EventIdentifier=4663)" -SourceIdentifier "powershell_browser_monitor"

Try {
    While ($True) {
        $NewEvent = Wait-Event -SourceIdentifier powershell_browser_monitor
        $Log = $NewEvent.SourceEventArgs.NewEvent.TargetInstance
        $LogName = $Log.LogFile
        $SourceName = $Log.SourceName
        $Category = $Log.CategoryString
        $EventID = $Log.EventCode
        $Time = $Log.TimeGenerated
        $Year = $Time.SubString(0, 4)
        $Month = $Time.SubString(4, 2)
        $Day = $Time.SubString(6, 2)
        $Hour = $Time.SubString(8, 2)
        $Minutes = $Time.SubString(10, 2)
        $Date = $Year + "/" + $Month + "/" + $Day + " " + $Hour + ":" + $Minutes
        $Date = (([DateTime]$Date)).AddHours(9).ToString("yyyy/MM/dd HH:mm:ss")

        $Message = $Log.Message
    
        $msg = $Message -split "`r`n"
        $msg2 = $msg | Select-Object -Skip 2
        
        $audit_4663 = @{}
        foreach ($m in $msg2) {
            if ($m.Trim() -eq "") {
                continue
            }
            $msg3 = $m.split(":", 2)
            $properties = $msg3[0].Trim()
            $value = $msg3[1].Trim()
            if ($properties -eq "" -or [bool]$audit_4663.PSObject.Properties[$properties]) {http://192.168.122.1:8000/
                continue
            }
            $audit_4663.Add($properties, $value)
        }
        
        $UserDomain = $audit_4663."Account Domain"
        $Username = $audit_4663."Account Name"
        $UserSID = $audit_4663."Security ID"
        $ProcId = [convert]::ToInt32($audit_4663."Process ID", 16)
        $Accesses = $audit_4663."Accesses"
        $TargetFile = $audit_4663."Object Name".ToLower()
        $ProcNamePath = $audit_4663."Process Name".ToLower()

        Write-Log-To-File $MainLogFile  "$Date - $LogName/$SourceName/$Category/$EventID`n"
        Write-Log-To-File $MainLogFile  "`t[+] $Username/$UserDomain($UserSID) execute $ProcId($ProcNamePath)`n"
        Write-Log-To-File $MainLogFile  "`t[+] $TargetFile ($Accesses)`n"
        
        if ($ProcId -eq 4 -or $ProcId -eq 0 -or $ProcId -eq $PID) {
            Write-Log-To-File $MainLogFile  "`t[+] Skip system access $ProcId($ProcNamePath)`n"
        }
        elseif ($TargetFile -notmatch $filemonRegex) {
            Write-Log-To-File $MainLogFile  "`t[+] Skip not browser file $TargetFile`n"
        }
        elseif ($ProcNamePath -match $processAlowRegex) {
            Write-Log-To-File $MainLogFile  "`t[+] Skip allowed process: $ProcNamePath`n"
        }
        else {
            Stop-Process -Id $ProcId -Force
            $alert = ""
            $alert += Write-Log-To-File $MainLogFile  "`t[!] Found suspicious behavior`n"
            $alert += Write-Log-To-File $MainLogFile  "`t[!] $ProcId($ProcNamePath): $TargetFile`n"
            $alert | msg *
        }

        Remove-Event powershell_browser_monitor
    }
    Catch {
        Write-Log-To-File $ErrorLogFile "$Date -- Error $Error[0]`n" 
    }
}
Finally {
    Get-Event | Remove-Event 
    Get-EventSubscriber | Unregister-Event 
    $nowTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    Write-Log-To-File $MainLogFile "`n$nowTime -- Session End--------------------------`n"
}