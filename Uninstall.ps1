#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

foreach ($taskName in @('Remote Logon Alert', 'Service Install Logger')) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Removed scheduled task: $taskName"
    }
}

Write-Host
Write-Host 'The %LOCALAPPDATA%\ParanoidPlus directory, logs, user PATH entry, and CurrentUser execution policy were left unchanged.'
Write-Host 'Remove or change those manually if desired.'
