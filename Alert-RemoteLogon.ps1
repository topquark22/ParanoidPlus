$since = (Get-Date).AddMinutes(-5)

$event = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $since
} -ErrorAction Stop |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    if ($data.LogonType -in '3', '10') {
        [pscustomobject]@{
            Time       = $_.TimeCreated
            LogonType  = $data.LogonType
            User       = $data.TargetUserName
            Domain     = $data.TargetDomainName
            SourceIP   = $data.IpAddress
            SourcePort = $data.IpPort
        }
    }
} |
Sort-Object Time -Descending |
Select-Object -First 1

if ($event) {
    $type = switch ($event.LogonType) {
        '3'  { 'Network' }
        '10' { 'RemoteInteractive / RDP' }
    }

    $message = @"
REMOTE LOGON DETECTED

Time: $($event.Time)
Type: $($event.LogonType) - $type
User: $($event.Domain)\$($event.User)
Source IP: $($event.SourceIP)
Source Port: $($event.SourcePort)
"@

    Add-Type -AssemblyName PresentationFramework

    1..3 | ForEach-Object {
        [System.Media.SystemSounds]::Hand.Play()
        Start-Sleep -Milliseconds 400
    }

    [System.Windows.MessageBox]::Show(
        $message,
        'Remote Logon Alert',
        'OK',
        'Warning'
    )
}
