function Write-Log-To-File {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [string]$LogText
    )
    Write-Host $LogText
    $LogText | Out-File $LogFile -Append
    
} 

$ErrorLogFile = "C:\powershel_browser_monitor_errorlog.txt" 

$MainLogFile = "C:\powershel_browser_monitor.txt" 

$nowTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")

Write-Log-To-File $MainLogFile "`n$nowTime -- New Session Start------------------------"

$processAlowRegex   = '(?i)^((c:\\windows\\system32\\svchost|c:\\windows\\explorer|(c:\\program files\\.*|c:\\program files \(x86\)\\.*|c:\\Users\\.*\\appdata\\Local\\.*)(firefox|chrome|edge|opera|coccoc|brave)))\.exe$'
$filemonRegex = '(?i).*\\Appdata\\.*(Chrome|Firefox|Edge|Opera|Coccoc|Brave).*(key4\.db|logins\.json|User Data.*\\Local State|User Data.*\\Login Data|Opera.*\\Login Data)$'# 

Register-WmiEvent -Query "Select * From __InstanceCreationEvent Where TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Security' AND (TargetInstance.EventCode=4663 OR TargetInstance.EventIdentifier=4663)" -SourceIdentifier "powershel_browser_monitor"

Try {
    While ($True) {
        $NewEvent = Wait-Event -SourceIdentifier powershel_browser_monitor
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
        $msg2 = $msg.replace(': ','=').replace('\','\\').replace(':', '=') # get rid of header 4664 data
        $msg3 = $msg2 | Select-Object -Skip 2
        $audit_4663 = $msg3 | ConvertFrom-StringData
        
        $UserDomain = $audit_4663."Account Domain"
        $Username = $audit_4663."Account Name"
        $UserSID = $audit_4663."Security ID"
        $ProcId = $audit_4663."Process ID"
        $Accesses = $audit_4663."Accesses"
        $TargetFile = $audit_4663."Object Name".ToLower().replace("c=", "c:")
        $ProcNamePath = $audit_4663."Process Name".ToLower().replace("c=", "c:")

        
        Write-Log-To-File $MainLogFile  "$Date - $LogName/$SourceName/$Category/$EventID"
        Write-Log-To-File $MainLogFile  "`t[+] $Username/$UserDomain($UserSID) execute $ProcId($ProcNamePath)"
        Write-Log-To-File $MainLogFile  "`t[+] $TargetFile ($Accesses)"
        
        if ($ProcId -eq 4 -or $ProcId -eq 0) {
            Write-Log-To-File $MainLogFile  "`t[+] Skip system access"
        }
        elseif ($TargetFile -notmatch $filemonRegex) {
            Write-Log-To-File $MainLogFile  "`t[+] Skip not browser file $TargetFile"
        }
        elseif ($ProcNamePath -match $processAlowRegex) {
            Write-Log-To-File $MainLogFile  "`t[+] Skip allowed process: $ProcNamePath"
        }
        else {
            Write-Log-To-File $MainLogFile  "`t[!] Found suspicious behavior"
            Write-Log-To-File $MainLogFile  "`t[!] $ProcId($ProcNamePath): $TargetFile"
            Stop-Process -Id $ProcId -Force
        }

        Remove-Event powershel_browser_monitor
    }
    Catch {
        Write-Log-To-File $ErrorLogFile "$Date -- Error $Error[0]" 
    }
}
Finally {
    Get-Event | Remove-Event 
    Get-EventSubscriber | Unregister-Event 
    $nowTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    Write-Log-To-File $MainLogFile "`n$nowTime -- Session End--------------------------"
}