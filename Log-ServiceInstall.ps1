$installDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logFile = Join-Path $installDir "ServiceInstall.log"
$idFile = Join-Path $installDir "ServiceInstall.lastid"

$lastId = 0
if (Test-Path $idFile) {
    $lastId = [long](Get-Content $idFile)
}

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 7045
} -ErrorAction Stop |
Where-Object {
    $_.RecordId -gt $lastId
} |
Sort-Object RecordId

foreach ($event in $events) {
    $message = $event.Message
    $suspicious = $false
    $reasons = @()

    $serviceName = $null
    $servicePath = $null

    if ($message -match 'Service Name:\s+(.+)') {
        $serviceName = $matches[1].Trim()
    }

    if ($message -match 'Service File Name:\s+(.+)') {
        $servicePath = $matches[1].Trim()
    }

    if ($servicePath -match '\\Users\\|\\AppData\\|\\Temp\\|\\Downloads\\') {
        $suspicious = $true
        $reasons += 'Service path is in a user-writable location'
    }

    $exePath = $servicePath

    if ($exePath -match '^"([^"]+)"') {
        $exePath = $matches[1]
    }
    elseif ($exePath -match '^([^\s]+\.exe|[^\s]+\.sys)') {
        $exePath = $matches[1]
    }

    if ($exePath -and (Test-Path $exePath)) {
        $sig = Get-AuthenticodeSignature $exePath

        if ($sig.Status -ne 'Valid') {
            $suspicious = $true
            $reasons += "Signature status is $($sig.Status)"
        }
    }
    elseif ($exePath) {
        $reasons += 'Service binary path could not be verified'
    }

    if ($serviceName -match 'anydesk|teamviewer|rustdesk|vnc|screenconnect|splashtop|logmein|remotepc|dwservice') {
        $suspicious = $true
        $reasons += 'Service name resembles remote-access software'
    }

    $entry = @"
============================================================
EventRecordID: $($event.RecordId)
Time: $($event.TimeCreated)
Suspicious: $(if ($suspicious) { 'Yes' } else { 'No' })
Reasons: $(if ($reasons.Count) { $reasons -join '; ' } else { 'None' })

Service Name: $serviceName
Service File: $servicePath

$($event.Message)

"@
    Add-Content -Path $logFile -Value $entry

    # WireGuard for Windows creates WireGuardTunnel$<tunnel-name> services
    # during tunnel activation. Log them, but do not alert on them.
    if ($suspicious -and $serviceName -notlike 'WireGuardTunnel$*') {
        Add-Type -AssemblyName PresentationFramework

        1..3 | ForEach-Object {
            [System.Media.SystemSounds]::Hand.Play()
            Start-Sleep -Milliseconds 400
        }

        $alertMessage = @"
SUSPICIOUS SERVICE INSTALLED

Time: $($event.TimeCreated)
Service: $serviceName
File: $servicePath

Reasons:
$($reasons -join "`n")
"@

        [Console]::Beep(1200, 500)
        [System.Windows.MessageBox]::Show(
            $alertMessage,
            'Suspicious Service Installation',
            'OK',
            'Warning'
        )
    }

    Set-Content -Path $idFile -Value $event.RecordId
}
