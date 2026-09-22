# Defender USB Guard

Small, auditable PowerShell + WPF GUI to harden Microsoft Defender against USB malware on Windows 10/11.

> **Status: untested first release.** The script has been reviewed line by line but has not yet been
> executed on a Windows machine. If something does not work, please
> [open an issue](https://github.com/dliebner/defender-usb-guard/issues) with the error text.

## What it does

Defender USB Guard is a single PowerShell 5.1 script (`DefenderUsbGuard.ps1`) plus a one-line launcher
(`Launch.cmd`). It shows a window with the current and desired state of a short list of Microsoft
Defender settings that stop malware arriving on USB sticks and memory cards: the "block untrusted and
unsigned processes that run from USB" Attack Surface Reduction (ASR) rule, scanning of removable drives,
turning AutoPlay off, and a handful of other ASR rules that rarely produce false alarms. Every change is
made with Microsoft's own cmdlets (`Set-MpPreference`, `Add-MpPreference`, `Remove-MpPreference`) or one
Explorer AutoPlay policy value. Before any change it writes a JSON snapshot of the current settings, and
any snapshot can be restored with the **Undo...** button. It was written as a fully readable alternative
to [ConfigureDefender](https://github.com/AndyFul/ConfigureDefender) for the narrow case of protecting a
home or small-office PC from infected removable media.

## Design constraints

1. **It touches only the listed settings.** Everything the tool can change is declared in one table
   (`$SettingDefs`) near the top of the script. There is no hidden "also fix this while we're here".
2. **Snapshot before every change.** Apply and Undo both save the current values to
   `%ProgramData%\DefenderUsbGuard\snapshots\snapshot-YYYYMMDD-HHmmss.json` before doing anything, so
   any change can be reverted with the tool or by reading the file and setting the values back by hand.
3. **No binary to trust.** There is nothing to download but a text file. What runs is what you can read.

## Settings it can change

The groups below match the groups in the script and in the window.

### USB and removable media

| Setting | Options | Recommended | How it is set |
|---|---|---|---|
| Block untrusted and unsigned processes that run from USB (ASR rule `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`) | Off, Audit, Warn, Block | Block | `Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions ...` |
| Scan removable drives during full scans | Off, On | On | `Set-MpPreference -DisableRemovableDriveScanning` |
| AutoPlay for all drives | Windows default, Disabled | Disabled | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` = `0xFF` (removed for "Windows default") |

### Other low false-alarm protections

| Setting | Options | Recommended | How it is set |
|---|---|---|---|
| Block executable content from email client and webmail (ASR rule `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`) | Off, Audit, Warn, Block | Block | `Add-MpPreference` (ASR) |
| Block credential stealing from LSASS (ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) | Off, Audit, Warn, Block | Block | `Add-MpPreference` (ASR) |
| Block persistence through WMI event subscription (ASR rule `e6db77e5-3df2-4cf1-b95a-636979351e5b`) | Off, Audit, Block (Defender does not support Warn for this rule) | Block | `Add-MpPreference` (ASR) |
| Block abuse of exploited vulnerable signed drivers (ASR rule `56a863a9-875e-4185-98a7-b882c64b5ce5`) | Off, Audit, Warn, Block | Block | `Add-MpPreference` (ASR) |
| Potentially unwanted application (PUA) protection | Off, Audit, Block | Block | `Set-MpPreference -PUAProtection` |

### Microsoft Office and Adobe Reader

These rules only matter if the application is installed. The script checks the registry App Paths for
Word, Excel, PowerPoint, Outlook and Adobe Reader/Acrobat; if the application is not found there is
no recommendation, the row says so, and **Set all to recommended** leaves that row unchanged. A rule
for an absent application costs nothing, so one that is already on is never turned off by the button.

| Setting | Options | Recommended | How it is set |
|---|---|---|---|
| Block Office applications from creating child processes (ASR rule `d4f940ab-401b-4efc-aadc-ad5f3c50688a`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Office applications from creating executable content (ASR rule `3b576869-a4ec-4529-8536-b80a7769e899`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Office applications from injecting code into other processes (ASR rule `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Win32 API calls from Office macros (ASR rule `92e97fa1-5d90-4c72-b1c2-b04d1b6ab7b7`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Office communication apps (Outlook) from creating child processes (ASR rule `26190899-1602-49e8-8b27-eb1d0a1ce869`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Adobe Reader from creating child processes (ASR rule `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c`) | Off, Audit, Warn, Block | Block if Adobe Reader is installed, else no change | `Add-MpPreference` (ASR) |

### Exclusions tab

The **Exclusions** tab adds or removes entries in Defender's *ASR-only* exclusion list
(`Add-MpPreference` / `Remove-MpPreference -AttackSurfaceReductionOnlyExclusions`). A file or folder
listed there is exempt from the ASR rules above but is still scanned for malware. Use it when a
legitimate program you run from a USB drive is blocked by a rule.

### Read-only information

The **Settings** tab also shows, for reference only, whether real-time protection, behaviour monitoring,
download/attachment scanning, script scanning, cloud-delivered protection and Tamper Protection are on,
plus the security intelligence version. The tool never changes these. The **Activity** tab lists ASR
block/audit events and malware detections from the Defender event log for the last 7, 30 or 90 days.

## What it deliberately does not do

- **No exclusions other than ASR-only exclusions.** It never adds a path, process or extension to the
  antivirus scan exclusion lists. Anything you exclude is still scanned for malware.
- **No policy-key wiping.** It never deletes or edits values under
  `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. If such values exist it warns you (see the Group
  Policy caveat below) and leaves them alone.
- **No network.** It downloads nothing, phones home to nothing, and checks for no updates.
- **Nothing left running.** It installs no service, scheduled task, startup entry or driver. When you
  close the window, nothing of it remains in memory. The only files it creates are the snapshots.
- **No changes to the core protections** (real-time protection, cloud protection, Tamper Protection,
  and so on). Those are shown for information and are managed by Windows.

## How to run it

1. Download `DefenderUsbGuard.ps1` and `Launch.cmd` into the same folder (or clone this repository).
2. Double-click `Launch.cmd`. It starts Windows PowerShell with
   `-ExecutionPolicy Bypass`, which applies to this one launch only and does not change the system's
   execution policy. You can also run the script directly:

   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File DefenderUsbGuard.ps1
   ```

3. Accept the **one UAC prompt**. The script needs administrator rights to talk to Defender and
   relaunches itself elevated.
4. Press **Set all to recommended** (or pick values row by row), then **Apply...**. The tool lists
   exactly what will change and asks for confirmation before saving a snapshot and applying.
5. **Reboot after applying ASR rules.** Rule changes made through `Add-MpPreference` are stored
   immediately, but a restart makes sure Defender and every already-running process pick them up.
6. To revert, press **Undo...**, choose a snapshot, and confirm. A snapshot of the current state is
   saved first, so Undo itself can be undone.

Requirements: Windows 10 version 1809 or later, or Windows 11; Microsoft Defender as the active
antivirus (a third-party antivirus disables it); Windows PowerShell 5.1, which is built in. No modules
need to be installed.

## Group Policy override caveat

Values under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (set by Group Policy, Intune or other
configuration tools) take precedence over anything set with `Set-MpPreference`. On a domain-joined or
MDM-managed PC, or one where another tool has written policy values, a change made here can appear to
succeed and then be silently ignored. The tool checks the root Windows Defender policy key and its ASR,
Scan and MpEngine subkeys, shows a red warning when values exist, and after Apply reports any setting whose readback does not match what you
asked for. It never removes those policy values; that is a decision for whoever put them there.

## Why not ConfigureDefender?

[ConfigureDefender](https://github.com/AndyFul/ConfigureDefender) is a well-known and far more complete
tool. This project exists for people who want a narrower one they can read in full:

- **Binaries only.** ConfigureDefender is distributed as compiled executables. You can verify the file
  hash, but you cannot read what it is about to do without decompiling it.
- **Source lags several versions.** The source published in its repository has trailed the released
  binaries by several versions, so even the readable part is not necessarily what you are running.
- **Unescaped exclusion paths.** Its exclusion handling has built PowerShell command lines from
  user-supplied paths without escaping them. Defender USB Guard passes paths directly as cmdlet
  arguments, so there is no command string for a path to break out of.

If you need to manage dozens of Defender settings, use ConfigureDefender. If you need the USB rules and a
few others, and you want to read every line of what runs, use this.

## Snapshot format

```json
{
  "Created": "2026-09-22T10:15:30.1234567-04:00",
  "Reason": "Before Apply",
  "Settings": {
    "asr_usb": "Off",
    "scan_removable": "On",
    "autoplay": "Windows default",
    "asr_email": "Off",
    "...": "..."
  }
}
```

Keys are the `Key` values from `$SettingDefs`; values are the option names shown in the window.

The snapshot folder is created with permissions that allow only Administrators and SYSTEM to write to
it, and those permissions are re-applied on every save, so another local user cannot plant or replace
snapshots. Undo also lists every change it is about to make and asks for confirmation.

## License

[MIT](LICENSE)
