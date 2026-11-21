# ParanoidPlus

ParanoidPlus is a small Windows monitoring toolkit for two things that are easy to miss during normal desktop use:

- successful **Type 3 (Network)** and **Type 10 (RemoteInteractive/RDP)** logons;
- installation of new Windows services, with extra attention given to service registrations that look unusual.

It is intentionally simple. ParanoidPlus uses Windows Event Logs, PowerShell, and Task Scheduler rather than installing a background agent of its own.

## What it installs

Scripts and configuration live under:

```text
%LOCALAPPDATA%\ParanoidPlus
```

Runtime data is kept in dedicated subdirectories:

```text
%LOCALAPPDATA%\ParanoidPlus\Logs
%LOCALAPPDATA%\ParanoidPlus\State
```

The installer adds the script directory to the current user's `PATH`.

ParanoidPlus has three monitoring scripts:

| File | Purpose |
| --- | --- |
| `Check-RemoteLogons.ps1` | Manual report of successful Type 3 and Type 10 logons since the last reboot, or all retained logons with `-All`. |
| `Alert-RemoteLogon.ps1` | Invoked by Task Scheduler when a matching Event 4624 occurs; logs new matching events and produces an audible warning and desktop dialog. |
| `Log-ServiceInstall.ps1` | Invoked on Event 7045; skips whitelisted services, logs other service installations, and alerts when an installation meets suspicious heuristics. |
| `ServiceWhitelist.txt` | User-editable service-name whitelist; matching services are skipped entirely. |

Two scheduled tasks are created:

```text
Remote Logon Alert
Service Install Logger
```

`Check-RemoteLogons.ps1` is deliberately **not** a scheduled task.

## Installation

1. Download or clone this repository.
2. Open **Windows PowerShell as Administrator**.
3. From the repository directory, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install.ps1
```

`Install.ps1`:

- creates `%LOCALAPPDATA%\ParanoidPlus` plus `Logs` and `State` subdirectories;
- initializes the remote-logon cursor on first install (without overwriting it on upgrades);
- copies the monitoring scripts there;
- creates `ServiceWhitelist.txt` on first install without overwriting later local edits;
- adds that directory to the user's persistent `PATH`;
- sets the current user's PowerShell execution policy to `RemoteSigned`;
- creates the `Remote Logon Alert` and `Service Install Logger` tasks;
- allows both tasks to run on battery power;
- sets multiple-instance handling to `Parallel`, so an open alert dialog does not block a later event.

The process-scoped `Bypass` used to launch the installer applies only to that PowerShell session.

## Remote logon monitoring

Windows Security Event **4624** records successful logons. ParanoidPlus watches for:

- **Logon Type 3** — Network
- **Logon Type 10** — RemoteInteractive / RDP

The real-time task uses an event subscription equivalent to:

```text
*[System[EventID=4624] and EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]
```

When one occurs, `Alert-RemoteLogon.ps1` sounds three 1200 Hz beeps and displays a topmost warning dialog with the time, account, source address, source port, and logon type. If the sound or popup raises an error, the script records it in `Logs\RemoteLogon.alert-errors.log`; a visible dialog still requires an interactive Windows desktop.

The same task writes **each new matching event** to:

```text
%LOCALAPPDATA%\ParanoidPlus\Logs\RemoteLogon.log
```

Each entry includes the Event Record ID, timestamp, logon type, account, source IP and port, workstation, and authentication package. The last successfully logged Event Record ID is stored in:

```text
%LOCALAPPDATA%\ParanoidPlus\State\RemoteLogon.lastid
```

The cursor and a per-user mutex prevent overlapping task instances from recording the same event repeatedly. A popup shows the latest newly processed logon; all matching events are logged. On first installation, the cursor starts at the current Security log position, so earlier logons are not backfilled. Reinstallation preserves the existing cursor and log. Logon events that have already expired from the Windows Security log cannot be recovered.

For a manual check at any time:

```powershell
Check-RemoteLogons.ps1
```

By default, the script limits its report to events since the most recent Windows boot. To search all successful Type 3 and Type 10 logons still retained in the Windows Security event log, including those from before the last reboot:

```powershell
Check-RemoteLogons.ps1 -All
```

The `-All` switch reports the timestamp of the oldest retained Security event, but does not recover events that Windows has already overwritten or cleared. Both modes filter by event ID and logon type within the Windows Event Log query.

### Testing the Type 3 alert

A reusable test script is available:

```powershell
.\test\Test-RemoteLogonAlert.ps1
```

It uses `net.exe`'s password prompt, so the password is not read or stored by the script.

An authenticated localhost SMB connection can be used for a controlled test.

First remove any existing mapping:

```cmd
net use \\localhost\IPC$ /delete
```

Then create a fresh connection:

```cmd
net use \\localhost\IPC$ /user:%COMPUTERNAME%\%USERNAME% *
```

A fresh Type 3 logon should be recorded in `Logs\RemoteLogon.log` and the alert task should run.

Clean up afterward:

```cmd
net use \\localhost\IPC$ /delete
```

Windows may reuse an existing SMB session, so deleting the old mapping first is important when repeating this test.

## Service-installation monitoring

Windows System Event **7045** records service installation.

`Log-ServiceInstall.ps1` records each new non-whitelisted 7045 event in:

```text
%LOCALAPPDATA%\ParanoidPlus\Logs\ServiceInstall.log
```

It also keeps the last processed Event Record ID in:

```text
%LOCALAPPDATA%\ParanoidPlus\State\ServiceInstall.lastid
```

Every log entry contains:

- Event Record ID;
- timestamp;
- `Suspicious: Yes` or `Suspicious: No`;
- the reasons for the classification;
- service name;
- service file/path;
- the original Event 7045 message.

### Suspicious-service heuristics

An installation is marked suspicious when one or more of the current heuristics match, including:

- the service binary is under a user-writable location such as `Users`, `AppData`, `Temp`, or `Downloads`;
- the referenced executable or driver exists but does not have a valid Authenticode signature;
- the service name resembles common remote-access software.

A `Suspicious: Yes` result means **inspect this event**. It does not prove malware.

Suspicious events produce an audible warning and a desktop dialog. Ordinary service installations are logged without a popup.

### Service alert whitelist

Alert exclusions are kept outside the PowerShell script in:

```text
%LOCALAPPDATA%\ParanoidPlus\ServiceWhitelist.txt
```

The file contains one PowerShell wildcard pattern per line, matched against the Windows service name. Blank lines and lines beginning with `#` are ignored. A matching service is skipped entirely: it is not written to `ServiceInstall.log` and does not produce the suspicious-service popup.

The default whitelist contains:

```text
WireGuardTunnel$*
```

WireGuard for Windows may install `WireGuardTunnel$<tunnel-name>` services as tunnels are activated. Keeping this pattern in the external whitelist avoids hard-coding WireGuard as a special case in `Log-ServiceInstall.ps1`.

To add another known service family, edit `ServiceWhitelist.txt`, for example:

```text
# Known internal service
MyKnownService*
```

Changes take effect the next time the service-install logger runs; no task reinstall is required.

### Testing the suspicious-service alert

A reusable test script is available for elevated PowerShell:

```powershell
.\test\Test-ServiceInstallAlert.ps1
```

It creates a unique temporary service, waits five seconds for the Event 7045 task, and then cleans up automatically.

A harmless test can be performed by copying a signed Windows executable to `%TEMP%` and registering it as a demand-start service. The service does not need to be started.

Run in elevated PowerShell:

```powershell
$testDir = "$env:TEMP\RemoteServiceTest"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Copy-Item "$env:WINDIR\System32\cmd.exe" "$testDir\remoteagent.exe" -Force

sc.exe create SuspiciousServiceTest `
    binPath= "`"$testDir\remoteagent.exe`" /c exit 0" `
    start= demand
```

Because the executable is under `%TEMP%`, ParanoidPlus should classify the event as suspicious, write it to the log, and display the warning.

Do **not** start the test service.

Clean up:

```powershell
sc.exe delete SuspiciousServiceTest
Remove-Item "$testDir" -Recurse -Force
```

If you repeat the test immediately, use a new service name if Windows is still holding the previous service registration open.

## Verify the scheduled tasks

```powershell
Get-ScheduledTask |
    Where-Object {
        $_.TaskName -in 'Remote Logon Alert','Service Install Logger'
    } |
    Select-Object TaskName,TaskPath,State
```

The expected Task Scheduler entries are:

```text
Remote Logon Alert
Service Install Logger
```

There is no `Check-RemoteLogon` or `Check-ServiceCreation` task.

## Uninstall

Run from an elevated PowerShell session:

```powershell
.\Uninstall.ps1
```

The current uninstaller removes the two scheduled tasks but intentionally leaves the installed scripts, logs, user `PATH` entry, and execution-policy setting intact.

## Security model and limitations

ParanoidPlus is a visibility tool, not an antivirus or endpoint-detection product.

It can tell you about the Windows events it watches; it cannot prove that a machine is uncompromised. In particular:

- malware already executing in an existing user session does not necessarily require a new Type 3 or Type 10 logon;
- software can persist through mechanisms other than service installation;
- Windows auditing must actually record an event for an event-driven monitor to see it;
- remote-logon logging requires the interactive user's event-triggered task to run before the corresponding Windows Security records expire;
- heuristic service classification can produce both false positives and false negatives.

Use the alerts as evidence to investigate, not as a substitute for normal endpoint security, backups, patching, and account protection.

## Files

```text
Alert-RemoteLogon.ps1
Check-RemoteLogons.ps1
Install.ps1
Log-ServiceInstall.ps1
ServiceWhitelist.txt
Uninstall.ps1
README.md
test\Test-RemoteLogonAlert.ps1
test\Test-ServiceInstallAlert.ps1
```
