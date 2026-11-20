$ErrorActionPreference = 'Stop'
$logDir = Join-Path $env:LOCALAPPDATA 'ParanoidPlus\Logs'
$stateDir = Join-Path $env:LOCALAPPDATA 'ParanoidPlus\State'
$logFile = Join-Path $logDir 'RemoteLogon.log'
$idFile = Join-Path $stateDir 'RemoteLogon.lastid'

New-Item -ItemType Directory -Path $logDir -Force | Out-Null
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

# Task Scheduler may launch this script in parallel for several nearby events.
$mutexName = 'Global\ParanoidPlusRemoteLogon-' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$hasMutex = $false
$event = $null

try {
    try {
        $hasMutex = $mutex.WaitOne()
    }
    catch [System.Threading.AbandonedMutexException] {
        $hasMutex = $true
    }

    $lastId = 0
    if (Test-Path $idFile) {
        $lastId = [long](Get-Content $idFile)
    }

    # The Security log may have been cleared, resetting its record IDs.
    $latestRecord = Get-WinEvent -LogName 'Security' -MaxEvents 1
    if ($latestRecord.RecordId -lt $lastId) {
        $lastId = 0
    }

    $xpath = "*[System[(EventID=4624) and (EventRecordID > $lastId)] and EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10')]]"
    $records = @()
    try {
        $records = @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath -ErrorAction Stop | Sort-Object RecordId)
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            throw
        }
    }

    foreach ($record in $records) {
        $xml = [xml]$record.ToXml()
        $data = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.Name] = $item.'#text'
        }

        if ($data.LogonType -notin '3', '10') {
            continue
        }

        $type = switch ($data.LogonType) {
            '3'  { 'Network' }
            '10' { 'RemoteInteractive / RDP' }
        }

        $entry = @"
============================================================
EventRecordID: $($record.RecordId)
Time: $($record.TimeCreated)
Type: $($data.LogonType) - $type
User: $($data.TargetDomainName)\$($data.TargetUserName)
Source IP: $($data.IpAddress)
Source Port: $($data.IpPort)
Workstation: $($data.WorkstationName)
Authentication Package: $($data.AuthenticationPackageName)

"@
        Add-Content -Path $logFile -Value $entry -ErrorAction Stop
        Set-Content -Path $idFile -Value $record.RecordId -ErrorAction Stop

        $event = [pscustomobject]@{
            Time       = $record.TimeCreated
            LogonType  = $data.LogonType
            User       = $data.TargetUserName
            Domain     = $data.TargetDomainName
            SourceIP   = $data.IpAddress
            SourcePort = $data.IpPort
        }
    }
}
finally {
    if ($hasMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}

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

    $alertErrorFile = Join-Path $logDir 'RemoteLogon.alert-errors.log'

    try {
        1..3 | ForEach-Object {
            [Console]::Beep(1200, 500)
            Start-Sleep -Milliseconds 200
        }
    }
    catch {
        Add-Content -Path $alertErrorFile -Value "$(Get-Date -Format o) Sound failed: $_" -ErrorAction SilentlyContinue
    }

    try {
        # Request a topmost warning on the interactive desktop.
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ParanoidPlusAlert {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int MessageBox(IntPtr window, string text, string caption, uint flags);
}
'@
        # MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST
        $result = [ParanoidPlusAlert]::MessageBox(
            [IntPtr]::Zero,
            $message,
            'Remote Logon Alert',
            0x00050030
        )
        if ($result -eq 0) {
            throw 'Windows MessageBox returned a failure result.'
        }
    }
    catch {
        Add-Content -Path $alertErrorFile -Value "$(Get-Date -Format o) Popup failed: $_" -ErrorAction SilentlyContinue
    }
}
