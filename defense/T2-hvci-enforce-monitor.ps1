#Requires -Version 5.1
<#
.SYNOPSIS
    T2 - HVCI/VBS enforcement + drift monitor. "Close the gap and warn if someone reopens it."

.DESCRIPTION
    Heart of the defense (doc 04, Pillar A). Two functions:
      (1) ENFORCE (-Enforce): sets registry policy so VBS + HVCI stay enabled, so the bypass
          technique cannot take hold. Idempotent. Requires a reboot.
      (2) MONITOR (-InstallMonitor): installs a scheduled task (at startup + every N minutes) that checks
          posture and, if it detects DRIFT (VBS/HVCI off, testsigning ON, Secure Boot OFF, or the
          appearance of HKLM\SOFTWARE\ManageVBS), writes an event to the Windows Event Log (source
          'HVGuard') and to a JSON log. This is the cleanest signal that someone set up/used the technique.

    Default mode (no switches) = STATUS ONLY (changes nothing). NEVER disables protections.

.PARAMETER Enforce           Applies the registry policy that enforces VBS+HVCI (reboot required).
.PARAMETER Lock              (with -Enforce) marks the config as locked (Locked=1). VERY hard to
                             revert without physical presence in UEFI. Explicit opt-in. Use with care.
.PARAMETER InstallMonitor    Installs the monitoring scheduled task.
.PARAMETER UninstallMonitor  Removes the scheduled task.
.PARAMETER IntervalMinutes   Monitor interval (def. 60).
.PARAMETER Force             Does not ask for confirmation on each change.
.PARAMETER AsJson / -JsonPath / -Quiet   Same as the rest of the suite.

.OUTPUTS
    Exit: 0 = enforced/monitor OK or posture already compliant | 1 = actions pending (or reboot) | 2 = error.

.NOTES
    Pairs with T5 (repair) and T3 (WDAC). Test ONLY on a Windows VM with snapshots. Requires Administrator.
    Version: 1.0.0
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Enforce,
    [switch]$Lock,
    [switch]$InstallMonitor,
    [switch]$UninstallMonitor,
    [int]$IntervalMinutes = 60,
    [switch]$Force,
    [switch]$AsJson,
    [string]$JsonPath,
    [switch]$Quiet
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$onWindows = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }
if (-not $onWindows) { Write-Error 'T2 only applies to Windows.'; exit 2 }
$IsElevated = $false
try { $IsElevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
$changing = $Enforce -or $InstallMonitor -or $UninstallMonitor
if ($changing -and -not $IsElevated) { Write-Error 'Requires Administrator for -Enforce/-InstallMonitor.'; exit 2 }

$actions = [System.Collections.Generic.List[object]]::new()
function Note($id,$name,$status,$evidence,[bool]$reboot=$false){ $actions.Add([pscustomobject]@{id=$id;name=$name;status=$status;evidence=$evidence;rebootRequired=$reboot}) }
function DoIt($target,$act){ if ($Force) { return $true } return $PSCmdlet.ShouldProcess($target,$act) }
function RegDword($p,$n){ try { return [int](Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { return $null } }
function SetDword($p,$n,$v){ if(-not(Test-Path $p)){New-Item -Path $p -Force|Out-Null}; New-ItemProperty -Path $p -Name $n -PropertyType DWord -Value $v -Force|Out-Null }

$dg   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$hvci = "$dg\Scenarios\HypervisorEnforcedCodeIntegrity"
$MonDir = "$env:ProgramData\HVGuard"
$MonScript = "$MonDir\hv-posture-monitor.ps1"
$TaskName = 'HVGuard-PostureMonitor'
$EvtSource = 'HVGuard'

# --------------------------------------------------------------------------------------------------
# Current runtime state (Win32_DeviceGuard)
# --------------------------------------------------------------------------------------------------
$vbsRun=$false;$hvciRun=$false
try {
    $d = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $vbsRun = ([int]$d.VirtualizationBasedSecurityStatus -eq 2)
    $run=@(); if($d.SecurityServicesRunning){$run=@($d.SecurityServicesRunning|%{[int]$_})}
    $hvciRun = ($run -contains 2)
} catch {}
Note 'STATE' 'Runtime state' 'INFO' ("VBS_running={0}; HVCI_running={1}" -f $vbsRun,$hvciRun)

# --------------------------------------------------------------------------------------------------
# (1) ENFORCE VBS + HVCI via registry
# --------------------------------------------------------------------------------------------------
if ($Enforce) {
    $lockVal = [int][bool]$Lock
    if (DoIt $dg 'Enforce VBS+HVCI (DeviceGuard registry)') {
        try {
            SetDword $dg   'EnableVirtualizationBasedSecurity' 1
            SetDword $dg   'RequirePlatformSecurityFeatures'   1     # 1 = Secure Boot
            SetDword $hvci 'Enabled'                           1
            if ($Lock) { SetDword $dg 'Locked' 1; SetDword $hvci 'Locked' 1 }
            $needReboot = (-not ($vbsRun -and $hvciRun)) -or [bool]$Lock   # reboot only if VBS/HVCI had to be started, or to apply -Lock
            Note 'ENF' 'Enforce VBS+HVCI' 'APPLIED' ("EnableVBS=1; HVCI.Enabled=1; Locked={0}{1}" -f $lockVal, $(if(-not $needReboot){' (already running)'}else{''})) $needReboot
        } catch { Note 'ENF' 'Enforce VBS+HVCI' 'ERROR' $_.Exception.Message }
    } else { Note 'ENF' 'Enforce VBS+HVCI' 'WOULD' 'Would set EnableVBS=1, HVCI.Enabled=1 (+Locked if -Lock)' $true }
} else {
    $e1 = RegDword $dg 'EnableVirtualizationBasedSecurity'; $e2 = RegDword $hvci 'Enabled'
    Note 'ENF' 'VBS+HVCI policy (registry)' $(if($e1 -eq 1 -and $e2 -eq 1){'OK'}else{'PENDING'}) ("EnableVBS={0}; HVCI.Enabled={1}. Use -Enforce to enforce it." -f $e1,$e2)
}

# --------------------------------------------------------------------------------------------------
# (2) MONITOR: embedded script + scheduled task
# --------------------------------------------------------------------------------------------------
$monitorBody = @'
# HVGuard - posture monitor (generated by T2). READ-ONLY: checks and logs drift.
$ErrorActionPreference = "SilentlyContinue"
$src = "HVGuard"; $logDir = "$env:ProgramData\HVGuard"; $log = "$logDir\posture-log.jsonl"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$bad = @()
try { $d = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard
      if ([int]$d.VirtualizationBasedSecurityStatus -ne 2) { $bad += "VBS not running" }
      $run=@(); if($d.SecurityServicesRunning){$run=@($d.SecurityServicesRunning|%{[int]$_})}
      if ($run -notcontains 2) { $bad += "HVCI not running" } } catch { $bad += "DeviceGuard not queryable" }
try { $bcd = & bcdedit /enum "{current}" | Out-String
      if ($bcd -match "(?im)^\s*testsigning\s+(Yes|On)\b") { $bad += "testsigning ON" } } catch {}
try { if (-not (Confirm-SecureBootUEFI)) { $bad += "Secure Boot OFF" } } catch {}
if (Test-Path "HKLM:\SOFTWARE\ManageVBS") { $bad += "IOC: ManageVBS present" }
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$rec = [pscustomobject]@{ timestampUtc=$ts; host=$env:COMPUTERNAME; drift=($bad.Count -gt 0); findings=$bad }
$rec | ConvertTo-Json -Compress | Add-Content -Path $log -Encoding utf8
try { [void][System.Diagnostics.EventLog]::SourceExists($src) } catch {}
if ($bad.Count -gt 0) {
    Write-EventLog -LogName Application -Source $src -EntryType Warning -EventId 7001 -Message ("HVGuard posture DRIFT: " + ($bad -join "; "))
} else {
    Write-EventLog -LogName Application -Source $src -EntryType Information -EventId 7000 -Message "HVGuard posture compliant (VBS+HVCI+SecureBoot OK, no IOC)."
}
'@

if ($InstallMonitor) {
    if (DoIt $TaskName 'Install monitor (scheduled task + event source)') {
        try {
            if (-not (Test-Path $MonDir)) { New-Item -Path $MonDir -ItemType Directory -Force | Out-Null }
            Set-Content -Path $MonScript -Value $monitorBody -Encoding utf8 -Force
            if (-not [System.Diagnostics.EventLog]::SourceExists($EvtSource)) { New-EventLog -LogName Application -Source $EvtSource }
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $MonScript)
            $t1 = New-ScheduledTaskTrigger -AtStartup
            $t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
            $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger @($t1,$t2) -Principal $pr -Force | Out-Null
            Note 'MON' 'Install monitor' 'APPLIED' ("task '{0}' every {1} min + at startup; script {2}; log {3}\posture-log.jsonl; events 7000/7001 in Application" -f $TaskName,$IntervalMinutes,$MonScript,$MonDir)
        } catch { Note 'MON' 'Install monitor' 'ERROR' $_.Exception.Message }
    } else { Note 'MON' 'Install monitor' 'WOULD' "Would create task '$TaskName' + event source '$EvtSource'" }
}
elseif ($UninstallMonitor) {
    if (DoIt $TaskName 'Remove monitor') {
        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; Note 'MON' 'Remove monitor' 'APPLIED' 'task removed' }
        catch { Note 'MON' 'Remove monitor' 'ERROR' $_.Exception.Message }
    } else { Note 'MON' 'Remove monitor' 'WOULD' "Would remove task '$TaskName'" }
}
else {
    $exists = $false; try { $exists = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) } catch {}
    Note 'MON' 'Monitor installed' $(if($exists){'OK'}else{'PENDING'}) $(if($exists){"task '$TaskName' present"}else{'Not installed. Use -InstallMonitor.'})
}

# --------------------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------------------
$err = @($actions | Where-Object { $_.status -eq 'ERROR' })
$would = @($actions | Where-Object { $_.status -eq 'WOULD' })
$reboot = @($actions | Where-Object { $_.rebootRequired -and $_.status -eq 'APPLIED' })
$pend = @($actions | Where-Object { $_.status -eq 'PENDING' })
if ($err.Count) { $overall='ERROR'; $exit=2 }
elseif ($would.Count -or $pend.Count -or $reboot.Count) { $overall='PENDING'; $exit=1 }
else { $overall='COMPLIANT'; $exit=0 }

$result=[ordered]@{ tool='T2-hvci-enforce-monitor'; version='1.0.0'
    timestampUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); hostname=$env:COMPUTERNAME
    elevated=$IsElevated; overall=$overall; exitCode=$exit; rebootRequired=($reboot.Count -gt 0); actions=@($actions) }
$json=$result|ConvertTo-Json -Depth 6
if ($JsonPath){ try{$json|Out-File -FilePath $JsonPath -Encoding utf8 -Force}catch{} }
if ($AsJson){ Write-Output $json }
elseif (-not $Quiet){
    Write-Host "`n=== T2 HVCI enforce/monitor - $overall (exit $exit) ===" -ForegroundColor Cyan
    foreach($a in $actions){ $c=switch($a.status){'APPLIED'{'Green'}'OK'{'Green'}'WOULD'{'Yellow'}'PENDING'{'Yellow'}'ERROR'{'Red'}default{'Gray'}}
        Write-Host ("  {0,-8} {1,-28} {2}" -f $a.status,$a.name,$a.evidence) -ForegroundColor $c }
    if($reboot.Count){ Write-Host 'REBOOT required for the enforced VBS/HVCI settings to take effect.' -ForegroundColor Yellow }
    Write-Host 'Verify with T1; complement with T3 (WDAC) and T4 (telemetry).' -ForegroundColor DarkGray; Write-Host ''
}
exit $exit
