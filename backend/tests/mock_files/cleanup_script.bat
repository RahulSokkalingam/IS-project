@echo off
:: Harmless Forensic Testing Script
echo [USB Artifact Test] Emulating suspicious persistence check...
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > nul 2>&1
echo Execution complete.
