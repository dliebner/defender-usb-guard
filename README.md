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

The groups below match the groups in the script and in the window. The rule GUIDs and the Warn-mode
support claims are checked automatically against Microsoft's published
[Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
by `tools/check_asr_docs.py`, which CI runs on every push and once a week.

### USB and removable media

| Setting | Options | Recommended | How it is set |
|---|---|---|---|
| Block untrusted and unsigned processes that run from USB (ASR rule `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`) | Off, Audit, Warn, Block | Block | `Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions ...` |
| Scan removable drives during full scans | Off, On | On | `Set-MpPreference -DisableRemovableDriveScanning` |
| AutoPlay for all drives (drive letters; phones and cameras connected as media devices use a separate policy the tool leaves alone) | Windows default, Disabled | Disabled | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` = `0xFF` (removed for "Windows default") |

**What the USB rule does and does not cover.** In Microsoft's words, it prevents unsigned or untrusted
executable files (.exe, .dll, .scr) from running from removable drives, and it also blocks those files
from running after they have been copied to disk. It does not stop a shortcut on the drive from starting
a signed Windows program, which is how some USB worms (Raspberry Robin, for example) chain `cmd.exe` and
`msiexec.exe`; catching those is the job of Defender's regular antivirus and behaviour monitoring, which
the Settings tab shows for reference. "Trusted" is a reputation decision, so keep cloud-delivered
protection on; the tab shows it in red when it is off.

### Other low false-alarm protections

| Setting | Options | Recommended | How it is set |
|---|---|---|---|
| Block executable content from email client and webmail (ASR rule `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`) | Off, Audit, Warn, Block | Block | `Add-MpPreference` (ASR) |
| Block credential stealing from LSASS (ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) | Off, Audit, Block (Defender does not support Warn for this rule) | Block | `Add-MpPreference` (ASR) |
| Block persistence through WMI event subscription (ASR rule `e6db77e5-3df2-4cf1-b95a-636979351e5b`; needs Windows 10 1903 or later) | Off, Audit, Warn, Block | Block | `Add-MpPreference` (ASR) |
| Block abuse of exploited vulnerable signed drivers (ASR rule `56a863a9-875e-4185-98a7-b882c64b5ce5`) | Off, Audit, Warn, Block | Block | `Add-MpPreference` (ASR) |
| Potentially unwanted application (PUA) protection | Off, Audit, Block | Block | `Set-MpPreference -PUAProtection` |

New Windows 11 installations (version 22H2 and later, on hardware that meets Microsoft's criteria)
enable LSA Protection by default, and Microsoft says the LSASS rule adds nothing where LSA Protection
is on. The rule still matters on Windows 10 and on systems upgraded from it. It also logs a large
volume of harmless events, which is why the Activity tab hides them by default.

### Microsoft Office and Adobe Reader

These rules only matter if the application is installed. The script checks the registry App Paths for
Word, Excel, PowerPoint and Outlook (the Office rules), for Outlook alone (the Outlook rule) and for
Adobe Reader/Acrobat; if the application is not found there is no recommendation, the row says so, and
**Set all to recommended** leaves that row unchanged. A rule for an absent application costs nothing,
so one that is already on is never turned off by the button.

Microsoft enforces the Office child-process, code-injection and Outlook rules only when Office is
installed under `%ProgramFiles%` or `%ProgramFiles(x86)%`. A Microsoft Store install of Office gets
neither protection nor false alarms from those three rules.

| Setting | Options | Recommended | How it is set |
|---|---|---|---|
| Block Office applications from creating child processes (ASR rule `d4f940ab-401b-4efc-aadc-ad5f3c50688a`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Office applications from creating executable content (ASR rule `3b576869-a4ec-4529-8536-b80a7769e899`) | Off, Audit, Warn, Block | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Office applications from injecting code into other processes (ASR rule `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84`) | Off, Audit, Block (Defender does not support Warn for this rule) | Block if Office is installed, else no change | `Add-MpPreference` (ASR) |
| Block Win32 API calls from Office macros (ASR rule `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b`) | Off, Audit, Warn, Block | Audit if Office is installed, else no change (history of false positives; no notification when it blocks) | `Add-MpPreference` (ASR) |
| Block Office communication apps (Outlook) from creating child processes (ASR rule `26190899-1602-49e8-8b27-eb1d0a1ce869`) | Off, Audit, Warn, Block | Block if Outlook is installed, else no change | `Add-MpPreference` (ASR) |
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
block/audit events, malware detections and Defender settings changes (event 5007, made by any tool)
from the Defender event log for the last 7, 30 or 90 days, with a per-rule filter and a "Hide LSASS
events" box that is checked by default. Fields are read from the event text on English Windows and
from the raw event properties on other languages.

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
5. **No reboot is needed.** ASR rule changes take effect immediately. If you changed the Office rules,
   restart the Office applications; Microsoft notes the code-injection rule needs that.
6. To revert, press **Undo...**, choose a snapshot, and confirm. A snapshot of the current state is
   saved first, so Undo itself can be undone.

Requirements: Windows 10 version 1809 or later, or Windows 11; Microsoft Defender as the active
antivirus (a third-party antivirus disables it); Windows PowerShell 5.1, which is built in. No modules
need to be installed.

## Group Policy override caveat

Values under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (set by Group Policy, Intune or other
configuration tools) take precedence over anything set with `Set-MpPreference`. On a domain-joined or
MDM-managed PC, or one where another tool has written policy values, a change made here can appear to
succeed and then be silently ignored. The tool checks the ASR, Scan and MpEngine policy keys, shows a red
warning when values exist, and after Apply reports any setting whose readback does not match what you
asked for. It never removes those policy values; that is a decision for whoever put them there.

## Why not ConfigureDefender?

[ConfigureDefender](https://github.com/AndyFul/ConfigureDefender) is a well-known and far more complete
tool. This project exists for people who want a narrower one they can read in full:

- **Binaries only.** ConfigureDefender is distributed as compiled executables. You can verify the file
  hash, but you cannot read what it is about to do without decompiling it.
- **Source lags several versions.** The source published in its repository has trailed the released
  binaries by several versions, so even the readable part is not necessarily what you are running.
- **Exclusion paths go through a command string.** Its exclusion feature builds PowerShell command
  lines that include user-supplied paths. Defender USB Guard passes paths directly as cmdlet arguments,
  so there is no command string for a path to break out of.

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

The tool's data folder, `%ProgramData%\DefenderUsbGuard`, is created with permissions that allow only
Administrators and SYSTEM to access it, and those permissions are re-applied on every save, so another
local user cannot plant or replace snapshots. Because of this the folder shows "access denied" when
opened in a normal Explorer window; Undo still works because the tool runs elevated. Undo also lists
every change it is about to make and asks for confirmation.

## License

[MIT](LICENSE)
