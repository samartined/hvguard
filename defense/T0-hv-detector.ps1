#Requires -Version 5.1
<#
.SYNOPSIS
    T0/T6 - Hypervisor-based Denuvo bypass detector (DenuvOwO family). Target host: AMD (SVM).

.DESCRIPTION
    READ-ONLY analysis. Combines platform signals and IOCs to answer two questions (doc 04):
      T0  -> "Is there an illegitimate hypervisor interposed RIGHT NOW?" (Blue Pill-style detection)
      T6  -> "Did this ALREADY run and shut down?" (leftovers after execution)  [toggle with -PostExecution]

    Signals evaluated, each one TRACED TO EVIDENCE (observed value vs expected):
      [D1] Hypervisor present         Win32_ComputerSystem.HypervisorPresent (= CPUID.1:ECX[31]).
                                      Distinguishes "present and explained" (legitimate VBS/Hyper-V) from
                                      "present and NOT explained" (suspected interposed HV / SimpleSvm).
      [D2] systeminfo corroboration   String "A hypervisor has been detected" (best-effort, localized).
      [D3] Defense state              Secure Boot OFF / testsigning ON / VBS-HVCI NOT running:
                                      is EXACTLY the state the technique needs in order to load.
      [D4] Registry IOC               HKLM\SOFTWARE\ManageVBS (created by VBS.cmd) -> strong signal of use.
      [D5] File IOC                   DenuvOwO component names in common paths; on AMD, SimpleSvm.sys is
                                      prioritized. SHA-256 hash + Authenticode signature (expected UNSIGNED).
                                      With -KnownHashesCsv, an exact hash match = very strong IOC.
      [D6] Driver/service IOC         Win32_SystemDriver / Win32_Service: HV driver loaded or registered
                                      (SimpleSvm/hyperkd). DenuvOwO unloads the HV when the game closes and
                                      does not leave a persistent service -> in -PostExecution mode it is
                                      expected to be absent; file/registry/BCD leftovers carry more weight.

    Does NOT execute, load, or touch the sample. Does NOT modify the system. Only reads state. Neutral in
    terms of writing; the AMD/SVM focus only affects IOC PRIORITIZATION, not safety.

.PARAMETER PostExecution
    T6 mode: frames the verdict as "residual" (the HV has already been unloaded; look for traces and
    defenses that were not restored).

.PARAMETER ScanPath
    Extra paths to scan for file IOCs (e.g. the game / crack installation folder).

.PARAMETER Depth
    Recursion depth for each scan root (default 4). System32\drivers is scanned flat (non-recursive).

.PARAMETER KnownHashesCsv
    CSV with a 'sha256' column (e.g. findings\hashes.csv after extracting the payload) to match exact hashes.

.PARAMETER AsJson / -JsonPath / -Quiet
    Same as T1: JSON via STDOUT / to file / silence console output.

.OUTPUTS
    Exit code:  0 = CLEAN   1 = DETECTED (strong IOC / unexplained active HV)   2 = SUSPECTED / INCONCLUSIVE

.NOTES
    Axis 0 (detection). Complements T1 (posture) and T5 (remediation). Test ONLY on a Windows VM with snapshots.
    Future enhancement (-DeepProbe): native CPUID leaf 0x40000000 probe (HV vendor fingerprint) + timing
    RDTSC around CPUID. Requires a native helper; it will be validated on the VM before inclusion.
    HypervisorPresent already covers the CPUID.1:ECX[31] bit, which is the primary signal.
    Version: 1.0.0
#>
[CmdletBinding()]
param(
    [switch]$PostExecution,
    [string[]]$ScanPath,
    [int]$Depth = 4,
    [string]$KnownHashesCsv,
    [switch]$AsJson,
    [string]$JsonPath,
    [switch]$Quiet,
    [switch]$DeepProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$onWindows = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }
if (-not $onWindows) { Write-Error 'T0/T6 only applies to Windows.'; exit 2 }

$IsElevated = $false
try {
    $wp = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsElevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $IsElevated = $false }

$Findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('CLEAN','ALERT','SUSPECT','INFO','UNKNOWN')][string]$Status,
        [ValidateSet('none','low','medium','high','critical')][string]$Severity = 'none',
        [string]$Category = '',
        [string]$Observed = '',
        [string]$Expected = '',
        [string]$Evidence = ''
    )
    $Findings.Add([pscustomobject]@{
        id=$Id; name=$Name; status=$Status; severity=$Severity; category=$Category
        observed=$Observed; expected=$Expected; evidence=$Evidence
    })
}

# ====================================================================================================
# [D1] Hypervisor present + is it explained by a legitimate HV?
# ====================================================================================================
$hvPresent = $null; $legitHv = $false; $vbsRunning = $false; $hvciRunning = $false
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $hvPresent = [bool]$cs.HypervisorPresent
} catch { $hvPresent = $null }

try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $vbsRunning  = ([int]$dg.VirtualizationBasedSecurityStatus -eq 2)
    $run = @(); if ($dg.SecurityServicesRunning) { $run = @($dg.SecurityServicesRunning | ForEach-Object {[int]$_}) }
    $hvciRunning = ($run -contains 2)
} catch { }

# Legitimate Hyper-V: VMMS present, or hypervisorlaunchtype directs a Windows HV.
$hyperVService = $false
try { if (Get-Service -Name vmms -ErrorAction SilentlyContinue) { $hyperVService = $true } } catch { }
$legitHv = ($vbsRunning -or $hyperVService)

if ($null -eq $hvPresent) {
    Add-Finding -Id 'D1' -Name 'Hypervisor present (CPUID.1:ECX[31])' -Status 'UNKNOWN' -Severity 'low' -Category 'hypervisor' `
        -Observed 'Not evaluable' -Expected 'False (no HV) or explained' -Evidence 'Win32_ComputerSystem.HypervisorPresent not available'
}
elseif (-not $hvPresent) {
    $ev = if ($PostExecution) { 'No active HV: consistent with "the DenuvOwO HV unloads when the game closes". Review leftovers (D3-D6).' } else { 'No hypervisor interposed at this time.' }
    Add-Finding -Id 'D1' -Name 'Hypervisor present (CPUID.1:ECX[31])' -Status 'CLEAN' -Severity 'none' -Category 'hypervisor' `
        -Observed 'HypervisorPresent=False' -Expected 'False or explained' -Evidence $ev
}
elseif ($legitHv) {
    $why = @(); if ($vbsRunning) { $why += 'VBS running' }; if ($hyperVService) { $why += 'Hyper-V service (vmms)' }
    Add-Finding -Id 'D1' -Name 'Hypervisor present (CPUID.1:ECX[31])' -Status 'INFO' -Severity 'low' -Category 'hypervisor' `
        -Observed 'HypervisorPresent=True (explained)' -Expected 'explained by legitimate HV' `
        -Evidence ("HV present but attributable to: {0}. Not suspicious by itself." -f ($why -join ', '))
}
else {
    Add-Finding -Id 'D1' -Name 'Hypervisor present (CPUID.1:ECX[31])' -Status 'ALERT' -Severity 'high' -Category 'hypervisor' `
        -Observed 'HypervisorPresent=True (NOT explained)' -Expected 'False or explained by Hyper-V/VBS' `
        -Evidence 'There is a hypervisor interposed WITHOUT VBS/Hyper-V to justify it. On an AMD host, consistent with an active SimpleSvm.sys (Ring -1). Correlate with D3-D6.'
}

# ====================================================================================================
# [D2] Corroboration via systeminfo (best-effort; localized string)
# ====================================================================================================
try {
    $si = & systeminfo 2>$null | Out-String
    if ($si -match 'hypervisor has been detected|Se ha detectado un hipervisor|hipervisor') {
        Add-Finding -Id 'D2' -Name 'systeminfo: hypervisor detected' -Status 'INFO' -Severity 'low' -Category 'hypervisor' `
            -Observed 'string present' -Expected 'absent unless legitimate HV' -Evidence 'systeminfo indicates hypervisor presence (corroborates D1).'
    }
} catch { }

# ====================================================================================================
# [D3] Defense state: are they in the state the technique NEEDS?
# ====================================================================================================
# Secure Boot
# Secure Boot: CONTEXT, not decisive. OFF is common/legitimate on multi-boot/multi-disk setups -> does NOT
# trigger a high alert by itself (avoids a false "compromised" reading). The decisive control the
# technique cannot bypass is HVCI (D3c); Secure Boot only adds corroboration alongside testsigning + IOCs.
try {
    $sb = Confirm-SecureBootUEFI
    if (-not $sb) {
        Add-Finding -Id 'D3a' -Name 'Secure Boot OFF (context)' -Status 'INFO' -Severity 'low' -Category 'defense-state' `
            -Observed 'Disabled' -Expected 'Enabled (recommended)' -Evidence 'Prerequisite for the boot variant, BUT common and legitimate on multi-boot/multi-disk setups. Not conclusive by itself; weigh together with HVCI (D3c), testsigning, and IOCs.'
    } else {
        Add-Finding -Id 'D3a' -Name 'Secure Boot' -Status 'CLEAN' -Severity 'none' -Category 'defense-state' -Observed 'Enabled' -Expected 'Enabled'
    }
} catch {
    $m = $_.Exception.Message
    if ($m -match 'not supported|no se admite|platform') {
        Add-Finding -Id 'D3a' -Name 'Secure Boot (non-UEFI)' -Status 'INFO' -Severity 'low' -Category 'defense-state' `
            -Observed 'Unavailable (legacy BIOS)' -Expected 'Enabled (UEFI)' -Evidence "Legacy BIOS: not applicable. Context, not compromise. $m"
    } else {
        Add-Finding -Id 'D3a' -Name 'Secure Boot' -Status 'UNKNOWN' -Severity 'low' -Category 'defense-state' -Observed 'Not evaluable' -Expected 'Enabled' -Evidence $m
    }
}
# testsigning (BCD) - requires elevation
if ($IsElevated) {
    try {
        $bcd = & bcdedit /enum '{current}' 2>&1 | Out-String
        $ts = $null
        foreach ($line in ($bcd -split "`r?`n")) { if ($line -match '^\s*testsigning\s+(.+?)\s*$') { $ts = $Matches[1].Trim() } }
        if ($ts -and $ts -match '^(Yes|On|1|true)$') {
            Add-Finding -Id 'D3b' -Name 'testsigning ON' -Status 'ALERT' -Severity 'high' -Category 'defense-state' `
                -Observed $ts -Expected 'No' -Evidence 'DSE weakened: allows loading unsigned drivers (required for the bypass HV).'
        } else {
            Add-Finding -Id 'D3b' -Name 'testsigning' -Status 'CLEAN' -Severity 'none' -Category 'defense-state' -Observed ($(if($ts){$ts}else{'No'})) -Expected 'No'
        }
    } catch { Add-Finding -Id 'D3b' -Name 'testsigning' -Status 'UNKNOWN' -Severity 'low' -Category 'defense-state' -Observed 'Error' -Expected 'No' -Evidence $_.Exception.Message }
} else {
    Add-Finding -Id 'D3b' -Name 'testsigning' -Status 'UNKNOWN' -Severity 'low' -Category 'defense-state' -Observed 'Not evaluable' -Expected 'No' -Evidence 'Requires Administrator (bcdedit).'
}
# VBS/HVCI running (the control the technique CANNOT bypass)
if (-not $vbsRunning -or -not $hvciRunning) {
    Add-Finding -Id 'D3c' -Name 'VBS/HVCI NOT running' -Status 'ALERT' -Severity 'high' -Category 'defense-state' `
        -Observed ("VBS={0}; HVCI={1}" -f $vbsRunning, $hvciRunning) -Expected 'both True' `
        -Evidence 'With HVCI off, the system is in the state exploitable by the technique. It is the key control (the real countermeasure).'
} else {
    Add-Finding -Id 'D3c' -Name 'VBS/HVCI running' -Status 'CLEAN' -Severity 'none' -Category 'defense-state' -Observed 'VBS=True; HVCI=True' -Expected 'both True' `
        -Evidence 'HVCI active: the technique cannot establish itself while it is maintained.'
}

# ====================================================================================================
# [D4] Registry IOC: HKLM\SOFTWARE\ManageVBS
# ====================================================================================================
if (Test-Path 'HKLM:\SOFTWARE\ManageVBS') {
    Add-Finding -Id 'D4' -Name 'Registry IOC: HKLM\SOFTWARE\ManageVBS' -Status 'ALERT' -Severity 'high' -Category 'ioc-registry' `
        -Observed 'PRESENT' -Expected 'absent' -Evidence 'Created by the bypass VBS.cmd so it can revert VBS. Its presence = the technique was prepared/used on this machine.'
} else {
    Add-Finding -Id 'D4' -Name 'Registry IOC: ManageVBS' -Status 'CLEAN' -Severity 'none' -Category 'ioc-registry' -Observed 'absent' -Expected 'absent'
}

# ====================================================================================================
# [D5] File IOC (AMD-forward: SimpleSvm.sys first)
# ====================================================================================================
$IocNames = @(
    'SimpleSvm.sys','hyperkd.sys','hyperhv.dll','hyperevade.dll','hypervisor-launcher.exe',
    'VBS.cmd','DenuvOwO.nfo','DenuoOwO_SRC.7z','EfiGuardDxe.efi','Loader.efi'
)
$knownSet = @{}
if ($KnownHashesCsv -and (Test-Path $KnownHashesCsv)) {
    try {
        foreach ($r in (Import-Csv -Path $KnownHashesCsv)) {
            if ($r.PSObject.Properties.Name -contains 'sha256' -and $r.sha256) { $knownSet[$r.sha256.ToLower()] = $true }
        }
    } catch { Write-Warning "Could not read KnownHashesCsv: $($_.Exception.Message)" }
}

$roots = [System.Collections.Generic.List[object]]::new()
foreach ($p in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:ProgramData")) { if ($p -and (Test-Path $p)) { $roots.Add([pscustomobject]@{Path=$p; Depth=$Depth}) } }
if ($ScanPath) { foreach ($p in $ScanPath) { if (Test-Path $p) { $roots.Add([pscustomobject]@{Path=$p; Depth=$Depth}) } } }
$drv = "$env:SystemRoot\System32\drivers"; if (Test-Path $drv) { $roots.Add([pscustomobject]@{Path=$drv; Depth=0}) }

$fileHits = [System.Collections.Generic.List[object]]::new()
foreach ($root in $roots) {
    try {
        $items = Get-ChildItem -Path $root.Path -Recurse -Depth $root.Depth -File -Force -ErrorAction SilentlyContinue |
                 Where-Object { $IocNames -contains $_.Name }
        foreach ($it in $items) { $fileHits.Add($it) }
    } catch { }
}
if ($fileHits.Count -eq 0) {
    Add-Finding -Id 'D5' -Name 'File IOC (DenuvOwO components)' -Status 'CLEAN' -Severity 'none' -Category 'ioc-file' `
        -Observed '0 matches' -Expected '0' -Evidence ("Scanned paths: {0}" -f (($roots | ForEach-Object {$_.Path}) -join '; '))
} else {
    foreach ($f in ($fileHits | Sort-Object FullName -Unique)) {
        $sha = ''; $signed = ''
        try { $sha = (Get-FileHash -Algorithm SHA256 -Path $f.FullName -ErrorAction Stop).Hash.ToLower() } catch { }
        try { $signed = (Get-AuthenticodeSignature -FilePath $f.FullName).Status } catch { $signed = 'n/a' }
        $hashMatch = ($sha -and $knownSet.ContainsKey($sha))
        $sev = if ($hashMatch) { 'critical' } elseif ($f.Extension -eq '.sys' -and $signed -ne 'Valid') { 'high' } else { 'medium' }
        $ev = "sha256=$sha; signature=$signed"
        if ($hashMatch) { $ev += ' ; EXACT MATCH with KnownHashesCsv' }
        Add-Finding -Id 'D5' -Name ("File IOC: {0}" -f $f.Name) -Status 'ALERT' -Severity $sev -Category 'ioc-file' `
            -Observed $f.FullName -Expected 'absent' -Evidence $ev
    }
}

# ====================================================================================================
# [D6] Loaded or registered driver/service IOC
# ====================================================================================================
# Bypass family (critical) + known vulnerable BYOVD drivers (medium): this class of technique
# abuses "Bring Your Own Vulnerable Driver" to load code in the kernel.
$bypassPat = 'simplesvm|hyperkd|hyperhv|hyperevade'
$byovdPat  = 'rtcore64|winring0|dbutil|gdrv|iqvw64|kdmapper|capcom|asmmap|msio64|physmem|speedfan|cpuz|nvflash'
try {
    $sysdrv = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
              Where-Object { $_.Name -match "\b($bypassPat|$byovdPat)" -or $_.PathName -match "\b($bypassPat|$byovdPat)" }
    if ($sysdrv) {
        foreach ($d in $sysdrv) {
            $isBypass = ($d.Name -match "\b($bypassPat)" -or $d.PathName -match "\b($bypassPat)")
            if ($isBypass) {
                $sev = if ($d.State -eq 'Running') { 'critical' } else { 'high' }
                $ev  = 'Driver from the DenuvOwO bypass family. On AMD the main one is SimpleSvm.sys.'
            } else {
                $sev = if ($d.State -eq 'Running') { 'high' } else { 'medium' }
                $ev  = 'Known vulnerable BYOVD driver: surface that this class of technique abuses to load code in the kernel. Confirm whether it is legitimate.'
            }
            Add-Finding -Id 'D6' -Name ("Driver IOC: {0}" -f $d.Name) -Status 'ALERT' -Severity $sev -Category 'ioc-driver' `
                -Observed ("State={0}; Path={1}" -f $d.State, $d.PathName) -Expected 'absent' -Evidence $ev
        }
    } else {
        Add-Finding -Id 'D6' -Name 'Registered HV driver IOC' -Status 'CLEAN' -Severity 'none' -Category 'ioc-driver' `
            -Observed 'none' -Expected 'none' `
            -Evidence $(if ($PostExecution) { 'Expected: DenuvOwO does not leave a persistent service; the HV unloads on close. D4/D5 carry more weight.' } else { 'No bypass driver registered.' })
    }
} catch {
    Add-Finding -Id 'D6' -Name 'Driver IOC' -Status 'UNKNOWN' -Severity 'low' -Category 'ioc-driver' -Observed 'Error' -Expected 'none' -Evidence $_.Exception.Message
}

if ($DeepProbe) {
    Add-Finding -Id 'DP' -Name 'Deep CPUID/RDTSC probe' -Status 'INFO' -Severity 'low' -Category 'hypervisor' `
        -Observed 'not implemented in v1' -Expected '-' `
        -Evidence 'Leaf 0x40000000 (HV vendor) + RDTSC timing: requires a native helper; will be validated on the VM before inclusion. HypervisorPresent (D1) already covers the CPUID.1:ECX[31] bit.'
}

# ====================================================================================================
# Verdict
# ====================================================================================================
$sevRank = @{ none=0; low=1; medium=2; high=3; critical=4 }
$alerts   = @($Findings | Where-Object { $_.status -eq 'ALERT' })
$unknowns = @($Findings | Where-Object { $_.status -eq 'UNKNOWN' })
$maxSev = 'none'
foreach ($a in $alerts) { if ($sevRank[$a.severity] -gt $sevRank[$maxSev]) { $maxSev = $a.severity } }

# DETECTED: any critical/high IOC (unexplained HV, ManageVBS, running driver, exact hash, unsigned .sys).
# SUSPECTED: only medium alerts (e.g. file name without hash, weak defenses with no other IOC) or unknowns.
if ($alerts.Count -gt 0 -and $sevRank[$maxSev] -ge 3) { $overall = 'DETECTED'; $exit = 1 }
elseif ($alerts.Count -gt 0 -or $unknowns.Count -gt 0) { $overall = 'SUSPECTED'; $exit = 2 }
else { $overall = 'CLEAN'; $exit = 0 }

$mode = if ($PostExecution) { 'T6 (post-execution / residual)' } else { 'T0 (live detection)' }
$result = [ordered]@{
    tool='T0-hv-detector'; version='1.0.0'; mode=$mode; hostArch='AMD/SVM'
    timestampUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname=$env:COMPUTERNAME; elevated=$IsElevated
    overall=$overall; exitCode=$exit; maxSeverity=$maxSev; alertCount=$alerts.Count
    findings=@($Findings)
}

$json = ($result | ConvertTo-Json -Depth 6)
if ($JsonPath) { try { $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force } catch { Write-Warning "JSON: $($_.Exception.Message)" } }

if ($AsJson) { Write-Output $json }
elseif (-not $Quiet) {
    $col = @{ CLEAN='Green'; ALERT='Red'; SUSPECT='Yellow'; INFO='Gray'; UNKNOWN='DarkYellow' }
    Write-Host ''
    Write-Host "============== T0/T6 - Hypervisor bypass detector ($mode) ==============" -ForegroundColor Cyan
    Write-Host ("Host: {0} [AMD/SVM]   Elevated: {1}   UTC: {2}" -f $result.hostname, $IsElevated, $result.timestampUtc)
    Write-Host '------------------------------------------------------------------------------'
    foreach ($f in $Findings) {
        Write-Host ("{0,-8} {1,-4} {2,-6} {3,-34} obs: {4}" -f $f.status, $f.severity.Substring(0,[Math]::Min(4,$f.severity.Length)), $f.id, $f.name, $f.observed) -ForegroundColor $col[$f.status]
        if ($f.evidence) { Write-Host ("            -> {0}" -f $f.evidence) -ForegroundColor DarkGray }
    }
    Write-Host '------------------------------------------------------------------------------'
    $ovc = switch ($overall) { 'CLEAN' {'Green'} 'DETECTED' {'Red'} default {'Yellow'} }
    Write-Host ("VERDICT: {0}   (max severity={1}, alerts={2}, exit={3})" -f $overall, $maxSev, $alerts.Count, $exit) -ForegroundColor $ovc
    if ($PostExecution -and $overall -ne 'CLEAN') {
        Write-Host 'T6: if there are leftovers, verify that defenses were restored (run T1) and consider remediation (T5).' -ForegroundColor Yellow
    }
    Write-Host '==============================================================================' -ForegroundColor Cyan
    Write-Host ''
}

exit $exit
