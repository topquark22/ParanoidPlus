$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

Write-Host "Last boot: $bootTime"
Write-Host "Checking successful Type 3 and Type 10 logons since boot..."
Write-Host

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $bootTime
} -ErrorAction Stop

$results = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()

    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    $logonType = $data.LogonType

    if ($logonType -in '3', '10') {
        [pscustomobject]@{
            Time        = $event.TimeCreated
            Type        = switch ($logonType) {
                '3'  { '3 - Network' }
                '10' { '10 - RemoteInteractive' }
            }
            User        = $data.TargetUserName
            Domain      = $data.TargetDomainName
            SourceIP    = $data.IpAddress
            SourcePort  = $data.IpPort
            Workstation = $data.WorkstationName
            Process     = $data.ProcessName
            LogonProc   = $data.LogonProcessName
            AuthPackage = $data.AuthenticationPackageName
        }
    }
}

if ($results) {
    $results |
        Sort-Object Time |
        Format-Table -AutoSize
}
else {
    Write-Host "No Type 3 or Type 10 successful logons since the last reboot."
}
