#Requires -Version 5.1
<#
.SYNOPSIS
    Defender USB Guard - a small, auditable GUI for a handful of Microsoft Defender hardening settings.

.DESCRIPTION
    Single-file PowerShell + WPF tool. It touches ONLY the settings listed in $SettingDefs below,
    using Microsoft's own cmdlets (Set-MpPreference / Add-MpPreference / Remove-MpPreference) plus
    one Explorer AutoPlay policy value. Before every Apply or Undo it saves a JSON snapshot of the
    current settings, and any snapshot can be restored. It installs nothing, leaves nothing running,
    and makes no network connections.

    Tabs:
      Settings   - current vs. desired state for each setting, with a recommended value.
      Activity   - Defender event log: ASR blocks/audits and malware detections (last 7/30/90 days).
      Exclusions - ASR-only exclusions for legitimate programs that get caught by a rule.

.NOTES
    Run:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File DefenderUsbGuard.ps1   (or Launch.cmd)
    Needs administrator rights; it relaunches itself elevated (one UAC prompt).
    Windows 10 1809+ or Windows 11, with Microsoft Defender as the active antivirus.
    Snapshots: %ProgramData%\DefenderUsbGuard\snapshots\
#>

$ErrorActionPreference = 'Stop'
$AppName     = 'Defender USB Guard'
$SnapshotDir = Join-Path $env:ProgramData 'DefenderUsbGuard\snapshots'

# ---------------------------------------------------------------------------------------------
# Elevation and apartment state (WPF needs STA; powershell.exe is STA by default)
# ---------------------------------------------------------------------------------------------
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin  = $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSta    = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
if (-not $isAdmin -or -not $isSta) {
    $relaunchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"")
    # Full path on purpose: a bare "powershell.exe" would be looked up in the current directory first.
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        if ($isAdmin) { Start-Process -FilePath $psExe -ArgumentList $relaunchArgs }
        else          { Start-Process -FilePath $psExe -ArgumentList $relaunchArgs -Verb RunAs }
    } catch {
        # Typically the user answered "No" to the UAC prompt. Say so; the console may be hidden.
        Add-Type -AssemblyName PresentationFramework
        [void][Windows.MessageBox]::Show("$AppName needs administrator rights and was not allowed to start elevated. Nothing was changed.`n`n$($_.Exception.Message)", $AppName, 'OK', 'Error')
        exit 1
    }
    exit
}

# Hide the console window if we were started with one visible.
try {
    Add-Type -Namespace DefenderUsbGuard -Name ConsoleWindow -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]   public static extern bool   ShowWindow(IntPtr hWnd, int nCmdShow);
'@
    $hConsole = [DefenderUsbGuard.ConsoleWindow]::GetConsoleWindow()
    if ($hConsole -ne [IntPtr]::Zero) { [void][DefenderUsbGuard.ConsoleWindow]::ShowWindow($hConsole, 0) }
} catch { }

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# ---------------------------------------------------------------------------------------------
# Setting definitions - the complete list of what this tool can change
# ---------------------------------------------------------------------------------------------
function Test-AppInstalled([string[]]$ExeNames) {
    $roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths'
    foreach ($exe in $ExeNames) { foreach ($root in $roots) { if (Test-Path (Join-Path $root $exe)) { return $true } } }
    return $false
}
$officeInstalled = Test-AppInstalled 'WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE', 'OUTLOOK.EXE'
$adobeInstalled  = Test-AppInstalled 'AcroRd32.exe', 'Acrobat.exe'

$AsrOptions = @('Off', 'Audit', 'Warn', 'Block')

$SettingDefs = @(
    # --- USB and removable media -----------------------------------------------------------
    @{ Key='asr_usb'; Type='ASR'; Guid='b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
       Category='USB and removable media'
       Name='Block untrusted and unsigned processes that run from USB'
       Description='Stops programs on a USB drive from running unless they are signed or trusted. "Warn" lets you allow a file after a prompt.'
       Options=$AsrOptions; Recommended='Block' }
    @{ Key='scan_removable'; Type='Removable'
       Category='USB and removable media'
       Name='Scan removable drives during full scans'
       Description='Includes USB drives and memory cards in full scans. Real-time protection already checks files as they are opened.'
       Options=@('Off', 'On'); Recommended='On' }
    @{ Key='autoplay'; Type='AutoPlay'
       Category='USB and removable media'
       Name='AutoPlay for all drives'
       Description='Stops Windows from offering to run or open content automatically when a drive or device is inserted.'
       Options=@('Windows default', 'Disabled'); Recommended='Disabled' }

    # --- Low false-alarm rules -------------------------------------------------------------
    @{ Key='asr_email'; Type='ASR'; Guid='be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
       Category='Other low false-alarm protections'
       Name='Block executable content from email client and webmail'
       Description='Blocks executable files (.exe, .dll, .scr) launched from Outlook or webmail attachments.'
       Options=$AsrOptions; Recommended='Block' }
    @{ Key='asr_lsass'; Type='ASR'; Guid='9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
       Category='Other low false-alarm protections'
       Name='Block credential stealing from LSASS'
       Description='Blocks tools that dump passwords from the Windows logon process.'
       Options=$AsrOptions; Recommended='Block' }
    @{ Key='asr_wmi'; Type='ASR'; Guid='e6db77e5-3df2-4cf1-b95a-636979351e5b'
       Category='Other low false-alarm protections'
       Name='Block persistence through WMI event subscription'
       Description='Blocks a stealthy technique malware uses to survive reboots.'
       Options=@('Off', 'Audit', 'Block'); Recommended='Block' }   # Defender does not support Warn for this rule
    @{ Key='asr_drivers'; Type='ASR'; Guid='56a863a9-875e-4185-98a7-b882c64b5ce5'
       Category='Other low false-alarm protections'
       Name='Block abuse of exploited vulnerable signed drivers'
       Description='Blocks known-vulnerable drivers that malware loads to disable security software.'
       Options=$AsrOptions; Recommended='Block' }
    @{ Key='pua'; Type='PUA'
       Category='Other low false-alarm protections'
       Name='Potentially unwanted application (PUA) protection'
       Description='Blocks adware, toolbars and software bundlers that are not outright malware.'
       Options=@('Off', 'Audit', 'Block'); Recommended='Block' }

    # --- Office / Adobe Reader (only useful if installed) ----------------------------------
    # When the application is not detected there is no recommendation (Recommended = $null):
    # "Set all to recommended" leaves the row as it is rather than turning off a rule that costs nothing.
    @{ Key='asr_office_child'; Type='ASR'; Guid='d4f940ab-401b-4efc-aadc-ad5f3c50688a'
       Category='Microsoft Office and Adobe Reader'
       Name='Block Office applications from creating child processes'
       Description='Stops macros from launching PowerShell, cmd and other programs.'
       Options=$AsrOptions; Recommended=$(if ($officeInstalled) { 'Block' } else { $null })
       Note=$(if ($officeInstalled) { '' } else { 'Office not detected on this PC' }) }
    @{ Key='asr_office_exec'; Type='ASR'; Guid='3b576869-a4ec-4529-8536-b80a7769e899'
       Category='Microsoft Office and Adobe Reader'
       Name='Block Office applications from creating executable content'
       Description='Stops macros from writing .exe, .dll and script files to disk.'
       Options=$AsrOptions; Recommended=$(if ($officeInstalled) { 'Block' } else { $null })
       Note=$(if ($officeInstalled) { '' } else { 'Office not detected on this PC' }) }
    @{ Key='asr_office_inject'; Type='ASR'; Guid='75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
       Category='Microsoft Office and Adobe Reader'
       Name='Block Office applications from injecting code into other processes'
       Description='Stops macro malware from hiding inside other running programs.'
       Options=$AsrOptions; Recommended=$(if ($officeInstalled) { 'Block' } else { $null })
       Note=$(if ($officeInstalled) { '' } else { 'Office not detected on this PC' }) }
    @{ Key='asr_office_api'; Type='ASR'; Guid='92e97fa1-5d90-4c72-b1c2-b04d1b6ab7b7'
       Category='Microsoft Office and Adobe Reader'
       Name='Block Win32 API calls from Office macros'
       Description='Blocks advanced macro attacks that call Windows directly.'
       Options=$AsrOptions; Recommended=$(if ($officeInstalled) { 'Block' } else { $null })
       Note=$(if ($officeInstalled) { '' } else { 'Office not detected on this PC' }) }
    @{ Key='asr_outlook'; Type='ASR'; Guid='26190899-1602-49e8-8b27-eb1d0a1ce869'
       Category='Microsoft Office and Adobe Reader'
       Name='Block Office communication apps (Outlook) from creating child processes'
       Description='Stops Outlook from launching other programs.'
       Options=$AsrOptions; Recommended=$(if ($officeInstalled) { 'Block' } else { $null })
       Note=$(if ($officeInstalled) { '' } else { 'Office not detected on this PC' }) }
    @{ Key='asr_adobe'; Type='ASR'; Guid='7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
       Category='Microsoft Office and Adobe Reader'
       Name='Block Adobe Reader from creating child processes'
       Description='Stops malicious PDFs from launching other programs.'
       Options=$AsrOptions; Recommended=$(if ($adobeInstalled) { 'Block' } else { $null })
       Note=$(if ($adobeInstalled) { '' } else { 'Adobe Reader not detected on this PC' }) }
)

# Friendly names for ASR rule IDs seen in the event log (display only; includes rules this tool does not set).
$AsrNames = @{
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Untrusted/unsigned processes from USB'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Executable content from email'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Credential stealing from LSASS'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'WMI event subscription persistence'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Vulnerable signed drivers'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Office child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Office executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Office code injection'
    '92e97fa1-5d90-4c72-b1c2-b04d1b6ab7b7' = 'Win32 API calls from macros'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Outlook child processes'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Adobe Reader child processes'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'JS/VBS launching downloaded executables'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Obfuscated scripts'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Prevalence/age/trusted-list rule'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced ransomware protection'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'PSExec/WMI process creation'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Reboot into Safe Mode'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Copied/impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Webshell creation (servers)'
}

# ---------------------------------------------------------------------------------------------
# Read / write helpers
# ---------------------------------------------------------------------------------------------
$AsrActionName = @{ 0 = 'Off'; 1 = 'Block'; 2 = 'Audit'; 5 = 'Off'; 6 = 'Warn' }   # 5 = NotConfigured, same effect as Off
$AsrActionArg  = @{ 'Off' = 'Disabled'; 'Block' = 'Enabled'; 'Audit' = 'AuditMode'; 'Warn' = 'Warn' }
$PuaArg        = @{ 'Off' = 'Disabled'; 'Block' = 'Enabled'; 'Audit' = 'AuditMode' }
$AutoPlayKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

function Get-AsrState([string]$Guid, $Pref) {
    $ids     = @($Pref.AttackSurfaceReductionRules_Ids)
    $actions = @($Pref.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i] -and ([string]$ids[$i] -eq $Guid)) {
            $a = [int]$actions[$i]
            if ($AsrActionName.ContainsKey($a)) { return $AsrActionName[$a] } else { return "Unknown($a)" }
        }
    }
    return 'Off'
}

function Get-AutoPlayState {
    $v = (Get-ItemProperty -Path $AutoPlayKey -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    if ($null -eq $v)   { return 'Windows default' }
    if ($v -eq 255)     { return 'Disabled' }
    return ('Custom (0x{0:X})' -f [int]$v)
}

function Set-AutoPlayState([string]$State) {
    if ($State -eq 'Windows default') {
        Remove-ItemProperty -Path $AutoPlayKey -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
        return
    }
    $value = 255
    if ($State -match '^Custom \(0x([0-9A-Fa-f]+)\)$') { $value = [Convert]::ToInt32($Matches[1], 16) }
    elseif ($State -ne 'Disabled') { throw "Unknown AutoPlay state '$State'" }
    if (-not (Test-Path $AutoPlayKey)) { New-Item -Path $AutoPlayKey -Force | Out-Null }
    New-ItemProperty -Path $AutoPlayKey -Name NoDriveTypeAutoRun -PropertyType DWord -Value $value -Force | Out-Null
}

function Get-SettingValue($Def, $Pref) {
    switch ($Def.Type) {
        'ASR'       { return (Get-AsrState $Def.Guid $Pref) }
        'Removable' { if ($Pref.DisableRemovableDriveScanning) { return 'Off' } else { return 'On' } }
        'PUA'       { switch ([int]$Pref.PUAProtection) { 0 { return 'Off' } 1 { return 'Block' } 2 { return 'Audit' } default { return "Unknown($($Pref.PUAProtection))" } } }
        'AutoPlay'  { return (Get-AutoPlayState) }
    }
    throw "Unknown setting type '$($Def.Type)'"
}

function Set-SettingValue($Def, [string]$Value) {
    $custom = ($Def.Type -eq 'AutoPlay' -and $Value -like 'Custom (0x*')
    if (-not $custom -and ($Def.Options -notcontains $Value)) { throw "Cannot set '$($Def.Name)' to '$Value'" }
    switch ($Def.Type) {
        'ASR'       { Add-MpPreference -AttackSurfaceReductionRules_Ids $Def.Guid -AttackSurfaceReductionRules_Actions $AsrActionArg[$Value] }
        'Removable' { Set-MpPreference -DisableRemovableDriveScanning ($Value -eq 'Off') }
        'PUA'       { Set-MpPreference -PUAProtection $PuaArg[$Value] }
        'AutoPlay'  { Set-AutoPlayState $Value }
    }
}

function Get-CoreStatus($Pref) {
    $s = Get-MpComputerStatus
    [pscustomobject]@{
        Items = @(
            @{ Name = 'Real-time protection';    Ok = [bool]$s.RealTimeProtectionEnabled }
            @{ Name = 'Behavior monitoring';     Ok = [bool]$s.BehaviorMonitorEnabled }
            @{ Name = 'Download/attachment scan'; Ok = [bool]$s.IoavProtectionEnabled }
            @{ Name = 'Script scanning';         Ok = (-not [bool]$Pref.DisableScriptScanning) }
            @{ Name = 'Cloud-delivered protection'; Ok = ([int]$Pref.MAPSReporting -ne 0) }
            @{ Name = 'Tamper Protection';       Ok = [bool]$s.IsTamperProtected }
        )
        SignatureVersion = $s.AntivirusSignatureVersion
        SignatureUpdated = $s.AntivirusSignatureLastUpdated
    }
}

function Test-PolicyOverrides {
    # Values under the Policies hive (Group Policy or other tools) override Set-MpPreference silently.
    $keys = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
    $found = @()
    foreach ($k in $keys) {
        if (Test-Path $k) {
            $props = (Get-ItemProperty -Path $k).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
            if ($props) { $found += $k }
        }
    }
    return $found
}

function Protect-SnapshotDir {
    # %ProgramData% lets any local user create files and folders, so restrict the snapshot folder to
    # Administrators and SYSTEM. Applied on every save, so a folder that already existed (possibly created
    # by another user) is corrected too, including its owner.
    $admins = New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)   # no inherited rules
    foreach ($sid in $admins, $system) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule ($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    $acl.SetOwner($admins)
    Set-Acl -Path $SnapshotDir -AclObject $acl
}

function Save-Snapshot([string]$Reason) {
    New-Item -ItemType Directory -Force -Path $SnapshotDir | Out-Null
    Protect-SnapshotDir
    $file = Join-Path $SnapshotDir ('snapshot-{0:yyyyMMdd-HHmmss}.json' -f (Get-Date))
    $data = [ordered]@{ Created = (Get-Date).ToString('o'); Reason = $Reason; Settings = [ordered]@{} }
    foreach ($row in $script:Rows) { $data.Settings[$row.Key] = $row.Current }
    $data | ConvertTo-Json -Depth 4 | Set-Content -Path $file -Encoding UTF8
    return $file
}

function Get-DefenderActivity([int]$Days) {
    $filter = @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(1116, 1117, 1121, 1122); StartTime = (Get-Date).AddDays(-$Days) }
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
    foreach ($e in $events) {
        $m = $e.Message
        if (-not $m) { $m = (($e.Properties | ForEach-Object { $_.Value }) -join ' | ') }
        $type = ''; $detail = ''; $path = ''; $extra = ''
        switch ($e.Id) {
            1121 { $type = 'ASR block' }
            1122 { $type = 'ASR audit' }
            1116 { $type = 'Malware detected' }
            1117 { $type = 'Action taken' }
        }
        if ($e.Id -in @(1121, 1122)) {
            if ($m -match 'ID:\s*\{?([0-9A-Fa-f-]{36})\}?') {
                $g = $Matches[1].ToLower()
                $detail = if ($AsrNames.ContainsKey($g)) { $AsrNames[$g] } else { $g }
            }
            if ($m -match '(?m)^\s*Path:\s*(.+?)\s*$')         { $path  = $Matches[1] }
            if ($m -match '(?m)^\s*Process Name:\s*(.+?)\s*$') { $extra = $Matches[1] }
        } else {
            if ($m -match '(?m)^\s*Name:\s*(.+?)\s*$')   { $detail = $Matches[1] }
            if ($m -match '(?m)^\s*Path:\s*(.+?)\s*$')   { $path   = $Matches[1] }
            if ($m -match '(?m)^\s*Action:\s*(.+?)\s*$') { $extra  = $Matches[1] }
        }
        [pscustomobject]@{ Time = $e.TimeCreated; Type = $type; Detail = $detail; Path = $path; Extra = $extra; Message = $m }
    }
}

# ---------------------------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------------------------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$AppName" Width="900" Height="720" MinWidth="720" MinHeight="540"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13" Background="#F3F3F3">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="14,6"/>
      <Setter Property="Margin" Value="6,0,0,0"/>
      <Setter Property="MinWidth" Value="90"/>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Bottom" Background="#E4E4E4" Padding="10,5">
      <TextBlock x:Name="StatusText" Text="Ready." TextTrimming="CharacterEllipsis"/>
    </Border>
    <TabControl x:Name="Tabs" Margin="10">

      <TabItem Header="  Settings  ">
        <DockPanel Margin="8">
          <Border DockPanel.Dock="Top" Background="White" BorderBrush="#D0D0D0" BorderThickness="1" CornerRadius="4" Padding="10,8" Margin="0,0,0,10">
            <StackPanel>
              <TextBlock Text="Core protections (shown for reference; managed by Windows)" FontWeight="SemiBold" Margin="0,0,0,4"/>
              <WrapPanel x:Name="CorePanel"/>
              <TextBlock x:Name="SignatureText" Foreground="#666666" Margin="0,4,0,0"/>
              <TextBlock x:Name="PolicyWarning" Foreground="#B00020" TextWrapping="Wrap" Margin="0,6,0,0" Visibility="Collapsed"/>
            </StackPanel>
          </Border>
          <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button x:Name="BtnRecommended" Content="Set all to recommended"/>
            <Button x:Name="BtnRefresh" Content="Refresh"/>
            <Button x:Name="BtnUndo" Content="Undo..."/>
            <Button x:Name="BtnApply" Content="Apply..." FontWeight="Bold"/>
          </StackPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="SettingsPanel" Margin="0,0,6,0"/>
          </ScrollViewer>
        </DockPanel>
      </TabItem>

      <TabItem Header="  Activity  ">
        <DockPanel Margin="8">
          <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
            <TextBlock Text="Defender events from the last" VerticalAlignment="Center"/>
            <ComboBox x:Name="ActivityDays" Width="60" Margin="6,0" SelectedIndex="1">
              <ComboBoxItem Content="7"/><ComboBoxItem Content="30"/><ComboBoxItem Content="90"/>
            </ComboBox>
            <TextBlock Text="days" VerticalAlignment="Center"/>
            <Button x:Name="BtnActivityRefresh" Content="Refresh" Margin="12,0,0,0"/>
            <TextBlock x:Name="ActivityCount" VerticalAlignment="Center" Margin="12,0,0,0" Foreground="#666666"/>
          </StackPanel>
          <TextBlock DockPanel.Dock="Bottom" Margin="0,6,0,0" Foreground="#666666" Text="Hover a row for the full event text."/>
          <DataGrid x:Name="ActivityGrid" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column"
                    GridLinesVisibility="Horizontal" CanUserAddRows="False" SelectionMode="Single" Background="White"
                    AlternatingRowBackground="#F7F7F7">
            <DataGrid.RowStyle>
              <Style TargetType="DataGridRow">
                <Setter Property="ToolTip" Value="{Binding Message}"/>
              </Style>
            </DataGrid.RowStyle>
            <DataGrid.Columns>
              <DataGridTextColumn Header="Time" Binding="{Binding Time, StringFormat='yyyy-MM-dd HH:mm'}" Width="125"/>
              <DataGridTextColumn Header="Event" Binding="{Binding Type}" Width="115"/>
              <DataGridTextColumn Header="Rule / threat" Binding="{Binding Detail}" Width="220"/>
              <DataGridTextColumn Header="File" Binding="{Binding Path}" Width="*"/>
              <DataGridTextColumn Header="Process / action" Binding="{Binding Extra}" Width="170"/>
            </DataGrid.Columns>
          </DataGrid>
        </DockPanel>
      </TabItem>

      <TabItem Header="  Exclusions  ">
        <DockPanel Margin="8">
          <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8"
                     Text="Files or folders listed here are exempt from Attack Surface Reduction rules only; they are still scanned for malware. Use this if a legitimate program is blocked by a rule."/>
          <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button x:Name="BtnExclAddFile" Content="Add file..."/>
            <Button x:Name="BtnExclAddFolder" Content="Add folder..."/>
            <Button x:Name="BtnExclRemove" Content="Remove selected"/>
          </StackPanel>
          <ListBox x:Name="ExclusionList" Background="White"/>
        </DockPanel>
      </TabItem>

    </TabControl>
  </DockPanel>
</Window>
"@

$Window = [Windows.Markup.XamlReader]::Parse($xaml)
$ui = @{}
foreach ($name in 'Tabs','StatusText','CorePanel','SignatureText','PolicyWarning','SettingsPanel','BtnRecommended','BtnRefresh','BtnUndo','BtnApply',
                  'ActivityDays','BtnActivityRefresh','ActivityCount','ActivityGrid','ExclusionList','BtnExclAddFile','BtnExclAddFolder','BtnExclRemove') {
    $ui[$name] = $Window.FindName($name)
}

function Set-Status([string]$Text) { $ui.StatusText.Text = $Text }
function Show-Info([string]$Text)   { [void][Windows.MessageBox]::Show($Window, $Text, $AppName, 'OK', 'Information') }
function Show-Error([string]$Text)  { [void][Windows.MessageBox]::Show($Window, $Text, $AppName, 'OK', 'Error') }
function T($l, $t, $r, $b) { New-Object Windows.Thickness -ArgumentList $l, $t, $r, $b }

function New-Text([string]$Text, [switch]$Bold, [string]$Color, [switch]$Wrap, [double]$Size = 0) {
    $tb = New-Object Windows.Controls.TextBlock
    $tb.Text = $Text
    if ($Bold)  { $tb.FontWeight = [Windows.FontWeights]::SemiBold }
    if ($Color) { $tb.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($Color)) }
    if ($Wrap)  { $tb.TextWrapping = 'Wrap' }
    if ($Size -gt 0) { $tb.FontSize = $Size }
    return $tb
}

$BrushNormal    = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#D0D0D0'))
$BrushChanged   = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#E8A317'))
$BrushBgNormal  = [Windows.Media.Brushes]::White
$BrushBgChanged = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#FFF8E1'))

function Update-RowHighlight($Row) {
    $changed = ($null -ne $Row.Current) -and ($Row.Combo.SelectedItem -ne $Row.Current)
    $Row.Border.BorderBrush = if ($changed) { $BrushChanged } else { $BrushNormal }
    $Row.Border.Background  = if ($changed) { $BrushBgChanged } else { $BrushBgNormal }
}

function New-SettingRow($Def) {
    $border = New-Object Windows.Controls.Border
    $border.BorderThickness = T 1 1 1 1; $border.BorderBrush = $BrushNormal; $border.Background = $BrushBgNormal
    $border.CornerRadius = New-Object Windows.CornerRadius -ArgumentList 4
    $border.Padding = T 10 8 10 8; $border.Margin = T 0 0 0 6

    $grid = New-Object Windows.Controls.Grid
    foreach ($w in @('*', '110', '150')) {
        $col = New-Object Windows.Controls.ColumnDefinition
        $col.Width = if ($w -eq '*') { New-Object Windows.GridLength -ArgumentList 1, ([Windows.GridUnitType]::Star) } else { New-Object Windows.GridLength -ArgumentList ([double]$w) }
        [void]$grid.ColumnDefinitions.Add($col)
    }

    $left = New-Object Windows.Controls.StackPanel
    [void]$left.Children.Add((New-Text $Def.Name -Bold))
    [void]$left.Children.Add((New-Text $Def.Description -Wrap -Color '#555555' -Size 12))
    if ($Def.Note) { [void]$left.Children.Add((New-Text $Def.Note -Color '#8A6D00' -Size 12)) }
    [Windows.Controls.Grid]::SetColumn($left, 0)

    $mid = New-Object Windows.Controls.StackPanel
    $mid.VerticalAlignment = 'Center'; $mid.Margin = T 10 0 0 0
    [void]$mid.Children.Add((New-Text 'Current' -Color '#888888' -Size 11))
    $currentText = New-Text '...' -Bold
    [void]$mid.Children.Add($currentText)
    [Windows.Controls.Grid]::SetColumn($mid, 1)

    $right = New-Object Windows.Controls.StackPanel
    $right.VerticalAlignment = 'Center'; $right.Margin = T 10 0 0 0
    [void]$right.Children.Add((New-Text 'Desired' -Color '#888888' -Size 11))
    $combo = New-Object Windows.Controls.ComboBox
    foreach ($o in $Def.Options) { [void]$combo.Items.Add($o) }
    [void]$right.Children.Add($combo)
    [void]$right.Children.Add((New-Text $(if ($Def.Recommended) { "Recommended: $($Def.Recommended)" } else { 'Recommended: no change' }) -Color '#888888' -Size 11))
    [Windows.Controls.Grid]::SetColumn($right, 2)

    [void]$grid.Children.Add($left); [void]$grid.Children.Add($mid); [void]$grid.Children.Add($right)
    $border.Child = $grid

    $row = [pscustomobject]@{ Key = $Def.Key; Def = $Def; Current = $null; Border = $border; CurrentText = $currentText; Combo = $combo }
    $combo.Tag = $row
    $combo.Add_SelectionChanged({ Update-RowHighlight $this.Tag })
    return $row
}

# Build the settings list, grouped by category.
$script:Rows = @()
foreach ($category in ($SettingDefs | ForEach-Object { $_.Category } | Select-Object -Unique)) {
    $header = New-Text $category -Bold -Size 14
    $header.Margin = T 0 8 0 6
    [void]$ui.SettingsPanel.Children.Add($header)
    foreach ($def in ($SettingDefs | Where-Object { $_.Category -eq $category })) {
        $row = New-SettingRow $def
        $script:Rows += $row
        [void]$ui.SettingsPanel.Children.Add($row.Border)
    }
}

# ---------------------------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------------------------
function Refresh-Settings([switch]$KeepDesired) {
    $pref = Get-MpPreference
    foreach ($row in $script:Rows) {
        $v = Get-SettingValue $row.Def $pref
        $row.Current = $v
        $row.CurrentText.Text = $v
        if (-not $row.Combo.Items.Contains($v)) { [void]$row.Combo.Items.Add($v) }
        if (-not $KeepDesired) { $row.Combo.SelectedItem = $v }
        Update-RowHighlight $row
    }

    $ui.CorePanel.Children.Clear()
    $core = Get-CoreStatus $pref
    foreach ($item in $core.Items) {
        $tb = New-Text (('{0} {1}' -f $(if ($item.Ok) { [char]0x25CF } else { [char]0x25CB }), $item.Name)) -Color $(if ($item.Ok) { '#1B7F3B' } else { '#B00020' })
        $tb.Margin = T 0 0 16 2
        if (-not $item.Ok) { $tb.FontWeight = [Windows.FontWeights]::SemiBold }
        [void]$ui.CorePanel.Children.Add($tb)
    }
    $ui.SignatureText.Text = 'Security intelligence version {0}, last updated {1:g}' -f $core.SignatureVersion, $core.SignatureUpdated

    $overrides = @(Test-PolicyOverrides)
    if ($overrides.Count -gt 0) {
        $ui.PolicyWarning.Text = "Policy values exist under:`n" + ($overrides -join "`n") + "`nThese come from Group Policy or another tool and may silently override what you set here."
        $ui.PolicyWarning.Visibility = 'Visible'
    } else {
        $ui.PolicyWarning.Visibility = 'Collapsed'
    }
}

# Shared by Apply and Undo: snapshot, apply each change, re-read, and report errors and values that did not take.
# $Changes is a list of objects with Row (a settings row) and Value (the option name to set). Returns the number applied without error.
function Invoke-Changes($Changes, [string]$SnapshotReason, [string]$Verb) {
    $snapshot = Save-Snapshot $SnapshotReason
    $errors = @()
    foreach ($c in $Changes) {
        try { Set-SettingValue $c.Row.Def $c.Value }
        catch { $errors += ('{0}: {1}' -f $c.Row.Def.Name, $_.Exception.Message) }
    }

    Refresh-Settings
    $notTaken = @($Changes | Where-Object { $_.Row.Current -ne $_.Value } | ForEach-Object { '  - {0} (still "{1}")' -f $_.Row.Def.Name, $_.Row.Current })

    $msg = "{0} {1} setting(s).`nSnapshot saved to:`n{2}" -f $Verb, ($Changes.Count - $errors.Count), $snapshot
    if ($errors.Count -gt 0)   { $msg += "`n`nErrors:`n" + ($errors -join "`n") }
    if ($notTaken.Count -gt 0) { $msg += "`n`nThese did not take effect (a policy may be overriding them):`n" + ($notTaken -join "`n") }
    if ($errors.Count -gt 0 -or $notTaken.Count -gt 0) { Show-Error $msg } else { Show-Info $msg }
    return ($Changes.Count - $errors.Count)
}

function Format-ChangeList($Changes) {
    return ($Changes | ForEach-Object { '  - {0}: {1}  ->  {2}' -f $_.Row.Def.Name, $_.Row.Current, $_.Value }) -join "`n"
}

function Invoke-Apply {
    Refresh-Settings -KeepDesired   # fresh "current" values, so the change list and snapshot are accurate
    $changes = @($script:Rows | Where-Object { $_.Combo.SelectedItem -ne $_.Current } | ForEach-Object { [pscustomobject]@{ Row = $_; Value = [string]$_.Combo.SelectedItem } })
    if ($changes.Count -eq 0) { Show-Info 'No changes to apply. Change a "Desired" value first.'; return }

    $list = Format-ChangeList $changes
    $answer = [Windows.MessageBox]::Show($Window, "The following settings will change:`n`n$list`n`nA snapshot of the current settings will be saved first so this can be undone.`n`nContinue?", $AppName, 'YesNo', 'Question')
    if ($answer -ne 'Yes') { Set-Status 'Apply cancelled.'; return }

    $applied = Invoke-Changes $changes 'Before Apply' 'Applied'
    Set-Status ('Applied {0} change(s) at {1:t}.' -f $applied, (Get-Date))
}

function Invoke-Undo {
    if (-not (Test-Path $SnapshotDir)) { Show-Info 'No snapshots yet. A snapshot is saved every time you press Apply.'; return }
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.InitialDirectory = $SnapshotDir; $dlg.Filter = 'Snapshots (*.json)|*.json'; $dlg.Title = 'Choose a snapshot to restore'
    if ($dlg.ShowDialog($Window) -ne $true) { return }

    Refresh-Settings -KeepDesired
    $snap = Get-Content -Path $dlg.FileName -Raw | ConvertFrom-Json
    $changes = @()
    foreach ($prop in $snap.Settings.PSObject.Properties) {
        $row = $script:Rows | Where-Object { $_.Key -eq $prop.Name }
        if ($row -and $row.Current -ne $prop.Value) { $changes += [pscustomobject]@{ Row = $row; Value = [string]$prop.Value } }
    }
    if ($changes.Count -eq 0) { Show-Info 'Current settings already match that snapshot.'; return }

    $list = Format-ChangeList $changes
    $answer = [Windows.MessageBox]::Show($Window, "Restore snapshot from $($snap.Created)?`n`n$list`n`nA snapshot of the current settings will be saved first.", $AppName, 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }

    [void](Invoke-Changes $changes 'Before Undo' 'Restored')
    Set-Status 'Snapshot restored.'
}

function Refresh-Activity {
    $days = [int]$ui.ActivityDays.SelectedItem.Content
    Set-Status "Reading Defender event log ($days days)..."
    $table = New-Object System.Data.DataTable
    foreach ($col in 'Type', 'Detail', 'Path', 'Extra', 'Message') { [void]$table.Columns.Add($col, [string]) }
    [void]$table.Columns.Add('Time', [datetime])
    $count = 0
    foreach ($ev in @(Get-DefenderActivity $days)) {
        $r = $table.NewRow()
        $r.Time = $ev.Time; $r.Type = $ev.Type; $r.Detail = $ev.Detail; $r.Path = $ev.Path; $r.Extra = $ev.Extra; $r.Message = $ev.Message
        $table.Rows.Add($r); $count++
    }
    $ui.ActivityGrid.ItemsSource = $table.DefaultView
    $ui.ActivityCount.Text = if ($count -eq 0) { 'No ASR or malware events in this period.' } else { "$count event(s)" }
    Set-Status 'Activity refreshed.'
}

function Refresh-Exclusions {
    $ui.ExclusionList.Items.Clear()
    foreach ($p in @((Get-MpPreference).AttackSurfaceReductionOnlyExclusions)) { if ($p) { [void]$ui.ExclusionList.Items.Add([string]$p) } }
}

function Add-Exclusion([string]$Path) {
    if (-not $Path) { return }
    # Passed directly as a cmdlet argument: no string-built command line, so any characters in the path are safe.
    Add-MpPreference -AttackSurfaceReductionOnlyExclusions $Path
    Refresh-Exclusions
    Set-Status "Added ASR exclusion: $Path"
}

# ---------------------------------------------------------------------------------------------
# Wire up events
# ---------------------------------------------------------------------------------------------
$ui.BtnRefresh.Add_Click({ try { Refresh-Settings; Set-Status 'Settings refreshed.' } catch { Show-Error $_.Exception.Message } })
$ui.BtnRecommended.Add_Click({ foreach ($row in $script:Rows) { if ($row.Def.Recommended) { $row.Combo.SelectedItem = $row.Def.Recommended } }; Set-Status 'Recommended values selected. Press Apply to make the changes.' })
$ui.BtnApply.Add_Click({ try { Invoke-Apply } catch { Show-Error $_.Exception.Message } })
$ui.BtnUndo.Add_Click({ try { Invoke-Undo } catch { Show-Error $_.Exception.Message } })
$ui.BtnActivityRefresh.Add_Click({ try { Refresh-Activity } catch { Show-Error $_.Exception.Message } })
$ui.BtnExclAddFile.Add_Click({
    try {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Title = 'Choose a file to exclude from ASR rules'; $dlg.Filter = 'All files (*.*)|*.*'
        if ($dlg.ShowDialog($Window) -eq $true) { Add-Exclusion $dlg.FileName }
    } catch { Show-Error $_.Exception.Message }
})
$ui.BtnExclAddFolder.Add_Click({
    try {
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Choose a folder to exclude from ASR rules'
        if ($dlg.ShowDialog() -eq 'OK') { Add-Exclusion $dlg.SelectedPath }
    } catch { Show-Error $_.Exception.Message }
})
$ui.BtnExclRemove.Add_Click({
    try {
        $sel = [string]$ui.ExclusionList.SelectedItem
        if (-not $sel) { return }
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $sel
        Refresh-Exclusions
        Set-Status "Removed ASR exclusion: $sel"
    } catch { Show-Error $_.Exception.Message }
})
$ui.Tabs.Add_SelectionChanged({
    if ($_.Source -ne $ui.Tabs) { return }
    try {
        switch ($ui.Tabs.SelectedIndex) {
            1 { if ($null -eq $ui.ActivityGrid.ItemsSource) { Refresh-Activity } }
            2 { Refresh-Exclusions }
        }
    } catch { Show-Error $_.Exception.Message }
})

# ---------------------------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------------------------
try {
    [void](Get-MpPreference)
} catch {
    [void][Windows.MessageBox]::Show("Could not talk to Microsoft Defender.`n`nMake sure Defender is the active antivirus and no third-party antivirus has disabled it.`n`n$($_.Exception.Message)", $AppName, 'OK', 'Error')
    exit 1
}
try { Refresh-Settings } catch { [void][Windows.MessageBox]::Show("Failed to read settings:`n$($_.Exception.Message)", $AppName, 'OK', 'Error'); exit 1 }
Set-Status 'Ready. Rows highlighted in yellow have a desired value that differs from the current one.'
[void]$Window.ShowDialog()
