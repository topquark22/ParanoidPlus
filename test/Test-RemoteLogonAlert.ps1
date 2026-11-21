$ErrorActionPreference = 'Stop'

$connection = '\\localhost\IPC$'
$user = "$env:COMPUTERNAME\$env:USERNAME"
$userArgument = "/user:$user"

Write-Host "Creating a fresh localhost SMB connection as $user"
Write-Host 'net.exe will prompt for the account password; this script does not read or store it.'
Write-Host

& cmd.exe /d /c "net use `"$connection`" /delete /y >nul 2>&1" | Out-Null

try {
    & net.exe use $connection $userArgument '*'
    if ($LASTEXITCODE -ne 0) {
        throw "net.exe use failed with exit code $LASTEXITCODE"
    }

    Write-Host
    Write-Host 'ParanoidPlus should record a Type 3 logon and display the remote-logon alert.'
    Write-Host 'Waiting 2 seconds before cleanup...'
    Start-Sleep -Seconds 2
}
finally {
    & cmd.exe /d /c "net use `"$connection`" /delete /y >nul 2>&1" | Out-Null
}

Write-Host 'Test cleanup complete.'
