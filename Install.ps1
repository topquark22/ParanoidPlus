#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:LOCALAPPDATA 'ParanoidPlus'
$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Write-Host "Installing Windows security monitoring for $env:USERDOMAIN\$env:USERNAME"

New-Item -ItemType Directory -Path $installDir -Force | Out-Null

$scriptNames = @(
    'Check-RemoteLogons.ps1',
    'Alert-RemoteLogon.ps1',
    'Log-ServiceInstall.ps1'
)

foreach ($name in $scriptNames) {
    Copy-Item (Join-Path $sourceDir $name) (Join-Path $installDir $name) -Force
}

$whitelistPath = Join-Path $installDir 'ServiceWhitelist.txt'
if (-not (Test-Path $whitelistPath)) {
    Copy-Item (Join-Path $sourceDir 'ServiceWhitelist.txt') $whitelistPath
}

Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if ($pathEntries -notcontains $installDir) {
    [Environment]::SetEnvironmentVariable(
        'Path',
        (($pathEntries + $installDir) -join ';'),
        'User'
    )
}
if (($env:Path -split ';') -notcontains $installDir) {
    $env:Path += ";$installDir"
}

function Register-EventTask {
    param(
        [Parameter(Mandatory)] [string] $TaskName,
        [Parameter(Mandatory)] [string] $Subscription,
        [Parameter(Mandatory)] [string] $ScriptPath,
        [Parameter(Mandatory)] [ValidateSet('IgnoreNew','Parallel')] [string] $MultipleInstancesPolicy
    )

    $escapedScriptPath = [System.Security.SecurityElement]::Escape($ScriptPath)
    $escapedSubscription = [System.Security.SecurityElement]::Escape($Subscription)
    $escapedUserId = [System.Security.SecurityElement]::Escape($userId)
    $escapedAuthor = [System.Security.SecurityElement]::Escape("$env:USERDOMAIN\$env:USERNAME")
    $startBoundary = (Get-Date).AddSeconds(-5).ToString('yyyy-MM-ddTHH:mm:ss')

    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$escapedAuthor</Author>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>$escapedUserId</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>$MultipleInstancesPolicy</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Triggers>
    <EventTrigger>
      <StartBoundary>$startBoundary</StartBoundary>
      <Enabled>true</Enabled>
      <Subscription>$escapedSubscription</Subscription>
    </EventTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File &quot;$escapedScriptPath&quot;</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
}

$remoteSubscription = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4624)] and EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10')]]</Select></Query></QueryList>
"@

$serviceSubscription = @"
<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[EventID=7045]]</Select></Query></QueryList>
"@

Register-EventTask `
    -TaskName 'Remote Logon Alert' `
    -Subscription $remoteSubscription `
    -ScriptPath (Join-Path $installDir 'Alert-RemoteLogon.ps1') `
    -MultipleInstancesPolicy 'Parallel'

Register-EventTask `
    -TaskName 'Service Install Logger' `
    -Subscription $serviceSubscription `
    -ScriptPath (Join-Path $installDir 'Log-ServiceInstall.ps1') `
    -MultipleInstancesPolicy 'Parallel'

Write-Host
Write-Host 'Installed:'
Write-Host "  $installDir\Check-RemoteLogons.ps1   (manual check; no scheduled task)"
Write-Host "  $installDir\ServiceWhitelist.txt     (service alert whitelist)"
Write-Host '  Scheduled task: Remote Logon Alert'
Write-Host '  Scheduled task: Service Install Logger'
Write-Host
Write-Host 'Both scheduled tasks may run on battery and use Parallel multiple-instance handling.'
Write-Host 'Open a new shell to inherit the persistent PATH change.'
