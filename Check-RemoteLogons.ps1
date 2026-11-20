param(
    [switch] $All
)

$timeFilter = ''
if ($All) {
    $firstEvent = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
    Write-Host "Checking successful Type 3 and Type 10 logons since $($firstEvent.TimeCreated) (oldest retained Security event)..."
}
else {
    $bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Write-Host "Last boot: $bootTime"
    Write-Host "Checking successful Type 3 and Type 10 logons since boot..."

    $sinceUtc = $bootTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $timeFilter = " and TimeCreated[@SystemTime >= '$sinceUtc']"
}
Write-Host

$xpath = "*[System[EventID=4624$timeFilter] and EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10')]]"

$events = @()
try {
    $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction Stop)
}
catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
        throw
    }
}

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
    if ($All) {
        Write-Host "No Type 3 or Type 10 successful logons in the retained Security log."
    }
    else {
        Write-Host "No Type 3 or Type 10 successful logons since the last reboot."
    }
}
