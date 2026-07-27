#Requires -Version 5.1
<#
.SYNOPSIS
    T1 - Defensive posture checker against the hypervisor-based Denuvo bypass (DenuvOwO family).

.DESCRIPTION
    READ-ONLY and IDEMPOTENT check of the state that *defeats* the Ring -1 bypass technique.
    The defensive thesis (doc 04) is that the technique DEPENDS on:
        - turning off Secure Boot,
        - weakening driver signing (DSE) via testsigning,
        - and VBS/HVCI NOT running.
    Therefore this script verifies that those controls are in the desired ("hardened") state:

        [C1] Secure Boot ...... ON  (CONTEXT, not decisive: commonly off on multi-boot setups; HVCI is the real countermeasure)
        [C2] Test signing (DSE) ......... OFF     (bcdedit / {current})   <- CORE
        [C3] VBS running ................ RUNNING (Win32_DeviceGuard.VirtualizationBasedSecurityStatus = 2)
        [C4] HVCI / Memory integrity .... RUNNING (Win32_DeviceGuard.SecurityServicesRunning contains 2)

    It also collects CORROBORATING EVIDENCE (does not change the core verdict, but is reported):
        - hypervisorlaunchtype (BCD)
        - DeviceGuard: EnableVirtualizationBasedSecurity / HVCI\Enabled (registry config)
        - Direct IOC: presence of HKLM\SOFTWARE\ManageVBS (tracking key created by VBS.cmd itself)

    Does NOT execute, load, or touch the sample. Does NOT modify the system. Only reads state.

.PARAMETER AsJson
    Emits the result as a single JSON object via STDOUT (for capture in a pipeline/SIEM).
    Suppresses human-readable console output.

.PARAMETER JsonPath
    In addition to the above, writes the JSON to the given path (telemetry artifact).

.PARAMETER Quiet
    Suppresses all console output; only sets the exit code (and writes JSON if -JsonPath).

.OUTPUTS
    Exit code:
        0 = PASS         -> all 4 core controls in the desired state. System hardened.
        1 = FAIL         -> at least one core control is NOT in the desired state (weak posture).
        2 = INCONCLUSIVE -> some control could not be evaluated (e.g. no privileges / non-UEFI) and there is no FAIL.

.NOTES
    Project: defensive forensic analysis (blue team). This script belongs to Axis A (safeguard), T1.
    Neutral to host architecture (Intel VMX / AMD SVM): all controls are Windows-platform controls.
    Requires administrator privileges for C1 (Secure Boot) and C2 (bcdedit); C3/C4 and the registry are
    read without elevation. Without admin, C1/C2 are marked INCONCLUSIVE (not a false FAIL).
    Test ONLY on a disposable Windows VM with snapshots (doc 03), never against the sample.
    Version: 1.0.0
#>
[CmdletBinding()]
param(
    [switch]$AsJson,
    [string]$JsonPath,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Semantic status codes per check -----------------------------------------------------------------
# PASS  = control in the desired state (defeats the technique)
# FAIL  = control in the state the technique NEEDS (weak posture / possible bypass preparation)
# WARN  = negative corroborating evidence, not core
# INFO  = contextual evidence
# UNKNOWN = not evaluable (no privileges, unsupported platform, error)

$script:Checks = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','WARN','INFO','UNKNOWN')][string]$Status,
        [string]$Observed = '',
        [string]$Expected = '',
        [string]$Evidence = '',
        [bool]$Core = $false
    )
    $script:Checks.Add([pscustomobject]@{
        id       = $Id
        name     = $Name
        status   = $Status
        observed = $Observed
        expected = $Expected
        evidence = $Evidence
        core     = $Core
    })
}

# --- Platform guards -----------------------------------------------------------------------------------
# In PS 6+, $IsWindows exists; in 5.1 it does not (and it is always Windows). We treat "undefined" as Windows.
$onWindows = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }
if (-not $onWindows) {
    Write-Error 'T1 only applies to Windows (the VBS/HVCI/Secure Boot controls are Windows-platform controls).'
    exit 2
}

# Elevation (required for C1 and C2).
$IsElevated = $false
try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = [Security.Principal.WindowsPrincipal]::new($wi)
    $IsElevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $IsElevated = $false }

# ====================================================================================================
# [C1] Secure Boot ON
# ====================================================================================================
# [C1] Secure Boot -- CONTEXT, NOT decisive (core=$false). Secure Boot OFF is a prerequisite of the
# BOOT VARIANT (EfiGuard) of the technique, BUT it is common and legitimate on multi-boot /
# multi-disk machines (e.g. dual boot with Linux). By itself it does NOT indicate compromise. The DECISIVE
# control the technique cannot bypass is HVCI (C4). That is why Secure Boot does not drag the verdict to FAIL.
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb) {
        Add-Check -Id 'C1' -Name 'Secure Boot' -Status 'PASS' -Core $false `
            -Observed 'Enabled' -Expected 'Enabled (recommended)' -Evidence 'Defense in depth. Not decisive: the real countermeasure is HVCI (C4).'
    } else {
        Add-Check -Id 'C1' -Name 'Secure Boot' -Status 'WARN' -Core $false `
            -Observed 'Disabled' -Expected 'Enabled (recommended)' `
            -Evidence 'OFF: common and LEGITIMATE on multi-boot/multi-disk setups; NOT conclusive by itself. Hardening recommended if your configuration allows it. The decisive factor is HVCI (C4).'
    }
} catch {
    $msg = $_.Exception.Message
    if ($msg -match 'not supported|no se admite|platform') {
        Add-Check -Id 'C1' -Name 'Secure Boot (non-UEFI)' -Status 'WARN' -Core $false `
            -Observed 'Unavailable (legacy BIOS)' -Expected 'Enabled (UEFI)' `
            -Evidence "Legacy BIOS: Secure Boot does not apply. Context, not compromise. The decisive factor is HVCI (C4). ($msg)"
    } elseif (-not $IsElevated) {
        Add-Check -Id 'C1' -Name 'Secure Boot' -Status 'UNKNOWN' -Core $false `
            -Observed 'Not evaluable' -Expected 'Enabled' -Evidence 'Requires running as Administrator'
    } else {
        Add-Check -Id 'C1' -Name 'Secure Boot' -Status 'UNKNOWN' -Core $false `
            -Observed 'Error' -Expected 'Enabled' -Evidence $msg
    }
}

# ====================================================================================================
# [C2] Test signing OFF  (+ hypervisorlaunchtype evidence)
# ====================================================================================================
if ($IsElevated) {
    try {
        $bcd = & bcdedit /enum '{current}' 2>&1 | Out-String
        # Value of a BCD element = everything that follows the element name on its line.
        function Get-BcdValue([string]$text, [string]$element) {
            foreach ($line in ($text -split "`r?`n")) {
                if ($line -match "^\s*$element\s+(.+?)\s*$") { return $Matches[1].Trim() }
            }
            return $null
        }
        $ts  = Get-BcdValue $bcd 'testsigning'
        $hlt = Get-BcdValue $bcd 'hypervisorlaunchtype'

        if ($null -eq $ts -or $ts -match '^(No|Off|0|false)$') {
            Add-Check -Id 'C2' -Name 'Test signing (DSE)' -Status 'PASS' -Core $true `
                -Observed ($(if ($ts) { $ts } else { 'No (default)' })) -Expected 'No' `
                -Evidence 'bcdedit: testsigning not active -> DSE not weakened by test-signing'
        } else {
            Add-Check -Id 'C2' -Name 'Test signing (DSE)' -Status 'FAIL' -Core $true `
                -Observed $ts -Expected 'No' `
                -Evidence 'bcdedit: testsigning ACTIVE -> allows loading unsigned drivers. Remediation: bcdedit /set testsigning off'
        }

        if ($hlt) {
            $st = if ($hlt -match '^(Off)$') { 'WARN' } else { 'INFO' }
            $ev = if ($hlt -match '^(Off)$') { 'hypervisorlaunchtype=Off -> prevents the VBS hypervisor from starting (VBS will not be able to run)' } else { "hypervisorlaunchtype=$hlt" }
            Add-Check -Id 'C2b' -Name 'hypervisorlaunchtype (BCD)' -Status $st -Observed $hlt -Expected 'Auto' -Evidence $ev
        }

        # nointegritychecks: another way (besides testsigning) to disable driver signing (DSE).
        $nic = Get-BcdValue $bcd 'nointegritychecks'
        if ($null -eq $nic -or $nic -match '^(No|Off|0|false)$') {
            Add-Check -Id 'C2c' -Name 'nointegritychecks (DSE)' -Status 'PASS' -Core $true `
                -Observed ($(if ($nic) { $nic } else { 'No (default)' })) -Expected 'No' `
                -Evidence 'bcdedit: nointegritychecks not active -> DSE not weakened via this route'
        } else {
            Add-Check -Id 'C2c' -Name 'nointegritychecks (DSE)' -Status 'FAIL' -Core $true `
                -Observed $nic -Expected 'No' `
                -Evidence 'bcdedit: nointegritychecks ACTIVE -> disables driver signing. Remediation: bcdedit /set nointegritychecks off'
        }
    } catch {
        Add-Check -Id 'C2' -Name 'Test signing (DSE)' -Status 'UNKNOWN' -Core $true `
            -Observed 'Error' -Expected 'No' -Evidence "bcdedit failed: $($_.Exception.Message)"
    }
} else {
    Add-Check -Id 'C2' -Name 'Test signing (DSE)' -Status 'UNKNOWN' -Core $true `
        -Observed 'Not evaluable' -Expected 'No' -Evidence 'bcdedit requires running as Administrator'
}

# ====================================================================================================
# [C3] VBS running  +  [C4] HVCI running   (Win32_DeviceGuard, does not require elevation)
# ====================================================================================================
# SecurityServices map: 1=Credential Guard, 2=HVCI, 3=System Guard Secure Launch, 4=SMM.
# VirtualizationBasedSecurityStatus: 0=off, 1=enabled-not-running, 2=running.
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
    $running   = @(); if ($dg.SecurityServicesRunning)    { $running   = @($dg.SecurityServicesRunning    | ForEach-Object { [int]$_ }) }
    $configured= @(); if ($dg.SecurityServicesConfigured) { $configured= @($dg.SecurityServicesConfigured | ForEach-Object { [int]$_ }) }

    $vbsText = switch ($vbsStatus) { 0 {'0 (not enabled)'} 1 {'1 (enabled, not running)'} 2 {'2 (running)'} default {"$vbsStatus (?)"} }
    if ($vbsStatus -eq 2) {
        Add-Check -Id 'C3' -Name 'VBS running' -Status 'PASS' -Core $true `
            -Observed $vbsText -Expected '2 (running)' -Evidence 'Win32_DeviceGuard.VirtualizationBasedSecurityStatus'
    } else {
        Add-Check -Id 'C3' -Name 'VBS running' -Status 'FAIL' -Core $true `
            -Observed $vbsText -Expected '2 (running)' `
            -Evidence 'VBS not running -> HVCI cannot be enforced; the state the technique needs'
    }

    if ($running -contains 2) {
        Add-Check -Id 'C4' -Name 'HVCI / Memory integrity running' -Status 'PASS' -Core $true `
            -Observed ('running=[{0}]' -f ($running -join ',')) -Expected 'includes 2 (HVCI)' `
            -Evidence 'Win32_DeviceGuard.SecurityServicesRunning contains 2 (HVCI). It is the real countermeasure: the technique CANNOT bypass it.'
    } else {
        Add-Check -Id 'C4' -Name 'HVCI / Memory integrity running' -Status 'FAIL' -Core $true `
            -Observed ('running=[{0}]' -f ($running -join ',')) -Expected 'includes 2 (HVCI)' `
            -Evidence 'HVCI NOT running -> allows loading the unsigned driver/hypervisor. It is the key control to restore.'
    }

    # Corroborating: configured vs running.
    Add-Check -Id 'C4b' -Name 'HVCI configured' -Status $(if ($configured -contains 2) {'INFO'} else {'WARN'}) `
        -Observed ('configured=[{0}]' -f ($configured -join ',')) -Expected 'includes 2' `
        -Evidence 'SecurityServicesConfigured (policy). If configured but not running: check reboot/hardware support.'
}
catch {
    Add-Check -Id 'C3' -Name 'VBS running' -Status 'UNKNOWN' -Core $true `
        -Observed 'Not evaluable' -Expected '2 (running)' -Evidence "Win32_DeviceGuard not available: $($_.Exception.Message)"
    Add-Check -Id 'C4' -Name 'HVCI / Memory integrity running' -Status 'UNKNOWN' -Core $true `
        -Observed 'Not evaluable' -Expected 'includes 2 (HVCI)' -Evidence 'Win32_DeviceGuard not available (old build or unsupported).'
}

# ====================================================================================================
# Registry evidence (VBS/HVCI config) - read without elevation
# ====================================================================================================
function Get-RegDword([string]$Path, [string]$Name) {
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return [int]$v.$Name
    } catch { return $null }
}
$dgKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$hvciKey = "$dgKey\Scenarios\HypervisorEnforcedCodeIntegrity"
$enVbs = Get-RegDword $dgKey 'EnableVirtualizationBasedSecurity'
$enHvci = Get-RegDword $hvciKey 'Enabled'
Add-Check -Id 'R1' -Name 'Registry: EnableVirtualizationBasedSecurity' -Status $(if ($enVbs -eq 1) {'INFO'} elseif ($null -eq $enVbs) {'INFO'} else {'WARN'}) `
    -Observed ($(if ($null -eq $enVbs) {'(absent)'} else {"$enVbs"})) -Expected '1' -Evidence "$dgKey\EnableVirtualizationBasedSecurity"
Add-Check -Id 'R2' -Name 'Registry: HVCI Enabled' -Status $(if ($enHvci -eq 1) {'INFO'} elseif ($null -eq $enHvci) {'INFO'} else {'WARN'}) `
    -Observed ($(if ($null -eq $enHvci) {'(absent)'} else {"$enHvci"})) -Expected '1' -Evidence "$hvciKey\Enabled"

# ====================================================================================================
# Additional hardening (not CORE for THIS bypass, but strengthens the anti-BYOVD surface)
# ====================================================================================================
$vdb = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
Add-Check -Id 'H1' -Name 'Vulnerable Driver Blocklist' -Status $(if ($vdb -eq 1) {'PASS'} else {'WARN'}) -Core $false `
    -Observed ($(if ($null -eq $vdb) {'(absent)'} else {"$vdb"})) -Expected '1 (recommended)' `
    -Evidence 'Microsoft vulnerable driver blocklist (anti-BYOVD). Remediation: T5 step R8.'
$sac = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
$sacTxt = switch ($sac) { 1 {'ON'} 2 {'evaluation'} default {'off/not supported'} }
Add-Check -Id 'H2' -Name 'Smart App Control' -Status 'INFO' -Core $false `
    -Observed $sacTxt -Expected 'ON (Win11 only + clean install)' -Evidence 'Informational: extra code-reputation layer (not critical for this bypass).'

# ====================================================================================================
# Direct IOC: HKLM\SOFTWARE\ManageVBS (tracking key created by the crack VBS.cmd)
# ====================================================================================================
$manageVbsPresent = Test-Path 'HKLM:\SOFTWARE\ManageVBS'
Add-Check -Id 'IOC1' -Name 'IOC: HKLM\SOFTWARE\ManageVBS' -Status $(if ($manageVbsPresent) {'WARN'} else {'INFO'}) `
    -Observed $(if ($manageVbsPresent) {'PRESENT'} else {'absent'}) -Expected 'absent' `
    -Evidence 'Its presence indicates the technique was PREPARED/USED on this machine (created by VBS.cmd so it can revert). It does not change the posture verdict, but it is a sign of configuration compromise.'

# ====================================================================================================
# Global verdict (only CORE checks count)
# ====================================================================================================
$coreChecks = @($script:Checks | Where-Object { $_.core })
$nFail = @($coreChecks | Where-Object { $_.status -eq 'FAIL' }).Count
$nUnknown = @($coreChecks | Where-Object { $_.status -eq 'UNKNOWN' }).Count

if ($nFail -gt 0)         { $overall = 'FAIL';         $exit = 1 }
elseif ($nUnknown -gt 0)  { $overall = 'INCONCLUSIVE'; $exit = 2 }
else                      { $overall = 'PASS';         $exit = 0 }

$iocHit = ($manageVbsPresent -eq $true)

$result = [ordered]@{
    tool         = 'T1-posture-check'
    version      = '1.0.0'
    timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname     = $env:COMPUTERNAME
    elevated     = $IsElevated
    overall      = $overall
    exitCode     = $exit
    iocDetected  = $iocHit
    checks       = @($script:Checks)
}

# --- Output -----------------------------------------------------------------------------------------
$json = ($result | ConvertTo-Json -Depth 6)
if ($JsonPath) {
    try { $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force } catch { Write-Warning "Could not write JSON to '$JsonPath': $($_.Exception.Message)" }
}

if ($AsJson) {
    Write-Output $json
}
elseif (-not $Quiet) {
    $sev = @{ PASS='Green'; FAIL='Red'; WARN='Yellow'; INFO='Gray'; UNKNOWN='DarkYellow' }
    Write-Host ''
    Write-Host '================ T1 - Posture checker (anti hypervisor bypass) ================' -ForegroundColor Cyan
    Write-Host ("Host: {0}    Elevated: {1}    UTC: {2}" -f $result.hostname, $IsElevated, $result.timestampUtc)
    Write-Host '--------------------------------------------------------------------------------------'
    foreach ($c in $script:Checks) {
        $tag = if ($c.core) { '[CORE]' } else { '      ' }
        $color = $sev[$c.status]
        Write-Host ("{0} {1,-8} {2,-6} {3,-42} obs: {4}" -f $tag, $c.status, $c.id, $c.name, $c.observed) -ForegroundColor $color
        if ($c.evidence) { Write-Host ("                     -> {0}" -f $c.evidence) -ForegroundColor DarkGray }
    }
    Write-Host '--------------------------------------------------------------------------------------'
    $ovColor = switch ($overall) { 'PASS' {'Green'} 'FAIL' {'Red'} default {'DarkYellow'} }
    Write-Host ("VERDICT: {0}   (core FAIL={1}, UNKNOWN={2}, exit={3})" -f $overall, $nFail, $nUnknown, $exit) -ForegroundColor $ovColor
    if ($iocHit) { Write-Host 'IOC ALERT: HKLM\SOFTWARE\ManageVBS present -> the technique was prepared/used on this machine.' -ForegroundColor Red }
    if (-not $IsElevated) { Write-Host 'NOTE: run as Administrator to evaluate Secure Boot and testsigning (currently INCONCLUSIVE).' -ForegroundColor Yellow }
    Write-Host '======================================================================================' -ForegroundColor Cyan
    Write-Host ''
}

exit $exit
