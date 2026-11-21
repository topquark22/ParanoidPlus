#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$serviceName = 'ParanoidPlusSuspiciousServiceTest-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$testDir = Join-Path $env:TEMP $serviceName
$exePath = Join-Path $testDir 'remoteagent.exe'
$serviceCreated = $false

Write-Host "Creating suspicious-service test: $serviceName"

New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Copy-Item "$env:WINDIR\System32\cmd.exe" $exePath -Force

try {
    $arguments = @(
        'create',
        $serviceName,
        'binPath=',
        "`"$exePath`" /c exit 0",
        'start=',
        'demand'
    )

    & sc.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create failed with exit code $LASTEXITCODE"
    }

    $serviceCreated = $true

    Write-Host
    Write-Host 'The service was created but will not be started.'
    Write-Host 'ParanoidPlus should log Event 7045, play the two-tone alert, and display the warning dialog.'
    Write-Host 'Waiting 5 seconds before cleanup...'
    Start-Sleep -Seconds 5
}
finally {
    if ($serviceCreated) {
        & sc.exe delete $serviceName | Out-Null
    }

    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Test cleanup complete.'
