@echo off
rem Starts Defender USB Guard. -ExecutionPolicy Bypass applies to this launch only; it does not change system policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0DefenderUsbGuard.ps1"
