@echo off
REM ============================================================================
REM  HVGuard - convenient launcher (double-click).
REM  Starts the PowerShell+WPF launcher. HVGuard.ps1 itself relaunches into the
REM  STA apartment (required for WPF) and auto-elevates to Administrator (UAC).
REM  If you cancel UAC, HVGuard starts in READ-ONLY MODE (Check/Analyze only).
REM  Does NOT disable any protection or run anything from the crack.
REM ============================================================================
setlocal
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
where pwsh.exe >nul 2>nul && set "PSEXE=pwsh.exe"
start "" "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0HVGuard.ps1" %*
endlocal
