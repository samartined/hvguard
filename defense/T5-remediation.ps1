#Requires -Version 5.1
<#
.SYNOPSIS
    T5 - Automatic remediation of the security weakening caused by the hypervisor-based bypass
    (DenuvOwO family). "Patches the holes the technique opens": restores kernel posture.

.DESCRIPTION
    The bypass technique needs to LEAVE the system in an insecure state (VBS/HVCI off, testsigning
    on, Secure Boot off, an unsigned driver loaded, a tracking key in the registry). This tool
    REVERTS those changes: it re-enables the protections and cleans up the leftovers. It ALWAYS
    moves in the safe direction.

    DESIGN GUARANTEE (important): this tool NEVER disables a protection or loads anything.
    It only (a) RE-ENABLES VBS/HVCI, (b) sets testsigning OFF, (c) ensures hypervisorlaunchtype=Auto,
    (d) removes the IOC key HKLM\SOFTWARE\ManageVBS, (e) unregisters a residual bypass driver
    (only via a name allowlist and only if it is NOT running), and (f) GUIDES re-enabling
    Secure Boot (cannot be done from the OS; it is a firmware step).

    Default mode = DRY-RUN (only reports what it would do). With -Apply it executes the changes.
    Every step has a PRE-check (is it needed?), an action, a POST-check and logging. Idempotent.
    Several changes require a REBOOT to take effect (this is indicated). It does not reboot on its
    own.

.PARAMETER Apply
    Executes the changes. Without this switch, it only reports (dry-run).

.PARAMETER Force
    With -Apply, skips the interactive confirmation prompt for each change.

.PARAMETER RemoveResidualDriver
    Allows unregistering (sc delete) a RESIDUAL bypass driver (allowlist, only if it is stopped).
    Disabled by default out of caution. Also requires -Apply.

.PARAMETER Only
    Comma-separated list of step IDs the user has CHOSEN to apply: e.g. 'R2,R5,R9'.
    It is an ALLOWLIST and fails closed: with -Only present, any change whose ID is not in the
    list is NOT applied (and is reported as 'SKIPPED'). Without -Only the classic behaviour is
    kept: everything needed is applied. This lets the GUI offer an "a la carte" repair without
    duplicating the engine logic. It does not affect dry-run (which always evaluates everything so
    it can be offered).

.PARAMETER LogPath
    Log file (append). By default it does not write a log file.

.PARAMETER AsJson / -JsonPath / -Quiet
    Same as T1/T0.

.OUTPUTS
    Exit: 0 = system already healthy or fully remediated | 1 = actions pending (dry-run, or applied
    but a reboot/manual UEFI step is missing) | 2 = errors during remediation.

.NOTES
    Axis B (repair), doc 04 T5. The MOST delicate tool -> dry-run by default + verification.
    Requires Administrator. Test ONLY on a disposable Windows VM with snapshots before using for
    real. Pairs with T1 (verify posture afterwards) and with T2/T3 (keep the holes closed: enforce
    HVCI + WDAC anti-unsigned-driver). Version: 1.1.0
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$Force,
    [switch]$RemoveResidualDriver,
    [string]$Only,
    [string]$LogPath,
    [switch]$AsJson,
    [string]$JsonPath,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Platform / elevation ---
$onWindows = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }
if (-not $onWindows) { Write-Error 'T5 only applies to Windows.'; exit 2 }

$IsElevated = $false
try {
    $wp = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsElevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $IsElevated = $false }
if (-not $IsElevated) {
    Write-Warning 'T5 requires running as Administrator to modify BCD/registry/services.'
    if ($Apply) { Write-Error 'Aborted: -Apply without Administrator privileges.'; exit 2 }
}

# --- Logging / steps infrastructure ---
$Steps = [System.Collections.Generic.List[object]]::new()
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = ('{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Msg)
    if ($LogPath) { try { Add-Content -Path $LogPath -Value $line -Encoding utf8 } catch {} }
    if (-not $Quiet -and -not $AsJson) {
        $c = switch ($Level) { 'FIX' {'Green'} 'WOULD' {'Yellow'} 'ERROR' {'Red'} 'MANUAL' {'Cyan'} 'OK' {'DarkGray'} default {'Gray'} }
        Write-Host $line -ForegroundColor $c
    }
}
# --- User selection (-Only): step-ID ALLOWLIST --------------------------------------------------------
# The user decides WHAT gets restored. With -Only, only the listed IDs are applied; the rest are
# still evaluated (so they can be reported) but are left untouched and marked 'SKIPPED'. Fail-closed:
# if a change does not declare its ID, with the filter active it is NOT applied.
$SelectedSet = @{}
if ($Only) { foreach ($s in ($Only -split '[,;\s]+')) { if ($s) { $SelectedSet[$s.Trim().ToLower()] = $true } } }
$HasFilter = ($SelectedSet.Count -gt 0)

function Test-StepSelected {
    param([string]$Id)
    if (-not $HasFilter) { return $true }
    if (-not $Id) { return $false }
    return $SelectedSet.ContainsKey($Id.ToLower())
}

function Add-StepResult {
    param($Id, $Name, [bool]$Needed, [string]$Status, [string]$Observed, [string]$Evidence,
          [bool]$RebootRequired = $false, [bool]$Manual = $false)
    # In -Apply mode with a user selection, "not applied by choice" != "pending from dry-run".
    if ($Apply -and $HasFilter -and $Status -eq 'WOULD_FIX') { $Status = 'SKIPPED' }
    $Steps.Add([pscustomobject]@{
        id=$Id; name=$Name; needed=$Needed; status=$Status; observed=$Observed
        evidence=$Evidence; rebootRequired=$RebootRequired; manual=$Manual
        selected=(Test-StepSelected -Id $Id)
    })
}
# Decides whether to actually execute a change (respects dry-run, the -Only selection, -Force and
# ShouldProcess).
function Confirm-Change {
    param([string]$Target, [string]$Action, [string]$Id)
    if (-not $Apply) { return $false }
    if (-not (Test-StepSelected -Id $Id)) { return $false }
    if ($Force) { return $true }
    return $PSCmdlet.ShouldProcess($Target, $Action)
}

# State helpers
function Get-BcdValue([string]$element) {
    try {
        $bcd = & bcdedit /enum '{current}' 2>&1 | Out-String
        foreach ($line in ($bcd -split "`r?`n")) {
            if ($line -match "^\s*$element\s+(.+?)\s*$") { return $Matches[1].Trim() }
        }
    } catch {}
    return $null
}
function Get-RegDword([string]$Path, [string]$Name) {
    try { return [int](Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}
function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

$dgKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$hvciKey = "$dgKey\Scenarios\HypervisorEnforcedCodeIntegrity"

# --- Platform state for VBS -------------------------------------------------------------------------
# VBS only STARTS if ALL the properties it requires (RequiredSecurityProperties) are AVAILABLE on
# the platform (AvailableSecurityProperties). RequirePlatformSecurityFeatures=1 requires Secure Boot,
# and =3 requires Secure Boot + DMA protection. On a machine with Secure Boot OFF, requiring it leaves
# VBS/HVCI "enabled, not running": UNABLE TO START. Since HVCI is the countermeasure the bypass
# CANNOT defeat, the priority is for HVCI to RUN -> we do not impose prerequisites the platform
# cannot meet. Secure Boot itself is left untouched: it continues to be measured, and its activation
# is guided separately (R7).
$SecPropName = @{ 0='Nothing'; 1='BaseVirtualizationSupport'; 2='SecureBoot'; 3='DmaProtection'
                  4='SecureMemoryOverwrite'; 5='NXProtections'; 6='SMMSecurityMitigations'
                  7='ModeBasedExecutionControl'; 8='ApicVirtualization' }
$dgWmi = $null
try { $dgWmi = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { }
$AvailProps = @(); $ReqProps = @()
if ($dgWmi) {
    try { $AvailProps = @($dgWmi.AvailableSecurityProperties | ForEach-Object { [int]$_ }) } catch { }
    try { $ReqProps   = @($dgWmi.RequiredSecurityProperties  | ForEach-Object { [int]$_ }) } catch { }
}
# Secure Boot "available for VBS" = property 2 present. If there is no WMI, we fall back to
# Confirm-SecureBootUEFI.
$SecureBootAvailable = $null
if ($AvailProps.Count -gt 0) { $SecureBootAvailable = ($AvailProps -contains 2) }
else { try { $SecureBootAvailable = [bool](Confirm-SecureBootUEFI) } catch { $SecureBootAvailable = $null } }
$DmaAvailable = ($AvailProps -contains 3)
# Prerequisites that are required but the platform does NOT offer -> these are why VBS fails to start.
$UnmetProps = @()
if ($AvailProps.Count -gt 0) { $UnmetProps = @($ReqProps | Where-Object { $_ -notin $AvailProps }) }
$UnmetText = (($UnmetProps | ForEach-Object { "$_=$($SecPropName[$_])" }) -join ', ')

Write-Log ("=== T5 remediation === mode: {0}" -f ($(if ($Apply) {'APPLY'} else {'DRY-RUN (only reports; use -Apply to make changes)'})))

# ====================================================================================================
# R1 - Re-enable VBS (DeviceGuard registry)  [requires reboot]
# ====================================================================================================
$enVbs = Get-RegDword $dgKey 'EnableVirtualizationBasedSecurity'
$needR1 = ($enVbs -ne 1)
if (-not $needR1) {
    Add-StepResult 'R1' 'VBS enabled (registry)' $false 'OK' "EnableVirtualizationBasedSecurity=$enVbs" 'Already at 1'
    Write-Log 'R1 VBS already enabled in registry' 'OK'
} else {
    if (Confirm-Change "$dgKey\EnableVirtualizationBasedSecurity" 'Set 1' -Id 'R1') {
        try {
            Set-RegDword $dgKey 'EnableVirtualizationBasedSecurity' 1
            # We only require Secure Boot as a VBS STARTUP prerequisite if the platform offers it.
            # Requiring it with Secure Boot OFF would leave VBS/HVCI unable to start (R1b unblocks this).
            if ($SecureBootAvailable -eq $true) { Set-RegDword $dgKey 'RequirePlatformSecurityFeatures' 1 }
            $post = Get-RegDword $dgKey 'EnableVirtualizationBasedSecurity'
            Add-StepResult 'R1' 'VBS enabled (registry)' $true 'FIXED' "-> $post" 'Requires a reboot to take effect' $true
            Write-Log 'R1 VBS enabled (reboot required)' 'FIX'
        } catch { Add-StepResult 'R1' 'VBS enabled (registry)' $true 'ERROR' '' $_.Exception.Message; Write-Log "R1 ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R1' 'VBS enabled (registry)' $true 'WOULD_FIX' "current=$enVbs" 'Would set EnableVirtualizationBasedSecurity=1 (reboot)' $true
        Write-Log 'R1 [dry-run] would enable VBS in registry' 'WOULD'
    }
}

# ====================================================================================================
# R1b - Unblock the STARTUP of VBS: remove prerequisites the platform CANNOT meet.
#       [requires reboot]
#       Does NOT disable any protection. On the contrary: this is what allows HVCI to actually RUN.
#       Symptom this fixes: VBS "enabled, not running" + an empty SecurityServicesRunning, because
#       Secure Boot is required and Secure Boot is OFF. Secure Boot itself is NOT changed (cannot be
#       done from the OS; see R7).
# ====================================================================================================
$rpsf = Get-RegDword $dgKey 'RequirePlatformSecurityFeatures'
$rpsfText = if ($null -ne $rpsf) { "$rpsf" } else { '(not set)' }
# We only act if something is required that the platform does not offer. Two possible fixes:
#   - Secure Boot not available  -> remove the value entirely (reverts to the Windows default).
#   - Secure Boot yes, DMA no (=3) -> lower to 1 (require only Secure Boot, which is present).
$needR1b = $false; $r1bAction = ''; $r1bTarget = $null
if ($null -ne $rpsf -and $rpsf -ge 1) {
    if ($SecureBootAvailable -eq $false) { $needR1b = $true; $r1bAction = 'remove'; }
    elseif ($rpsf -eq 3 -and -not $DmaAvailable) { $needR1b = $true; $r1bAction = 'lower'; $r1bTarget = 1 }
}
if (-not $needR1b) {
    $obs = "RequirePlatformSecurityFeatures=$rpsfText; SecureBoot available=$SecureBootAvailable"
    $ev  = if ($UnmetProps.Count -gt 0) { "Unmet prerequisites: $UnmetText" } else { 'All VBS prerequisites are meetable' }
    Add-StepResult 'R1b' 'VBS can start (prerequisites meetable)' $false 'OK' $obs $ev
    Write-Log 'R1b VBS prerequisites are meetable' 'OK'
} else {
    $why = ("Secure Boot is required (RequirePlatformSecurityFeatures={0}) but the platform does NOT offer it " -f $rpsf) +
           ("(missing: {0}) -> VBS/HVCI remain 'enabled, not running' and provide NO protection. " -f $(if ($UnmetText) { $UnmetText } else { 'SecureBoot' })) +
           'Removing that prerequisite does NOT disable anything: it is what allows HVCI -the countermeasure ' +
           'the bypass cannot defeat- to actually RUN. Secure Boot is left unchanged and its activation is guided in R7.'
    $act = if ($r1bAction -eq 'remove') { 'Remove RequirePlatformSecurityFeatures' } else { "Lower RequirePlatformSecurityFeatures to $r1bTarget" }
    if (Confirm-Change "$dgKey\RequirePlatformSecurityFeatures" $act -Id 'R1b') {
        try {
            if ($r1bAction -eq 'remove') {
                Remove-ItemProperty -Path $dgKey -Name 'RequirePlatformSecurityFeatures' -Force -ErrorAction Stop
            } else {
                Set-RegDword $dgKey 'RequirePlatformSecurityFeatures' $r1bTarget
            }
            $post = Get-RegDword $dgKey 'RequirePlatformSecurityFeatures'
            $ok = if ($r1bAction -eq 'remove') { ($null -eq $post) } else { ($post -eq $r1bTarget) }
            $postText = if ($null -eq $post) { '(removed)' } else { "$post" }
            Add-StepResult 'R1b' 'Unblock the startup of VBS/HVCI' $true ($(if ($ok) { 'FIXED' } else { 'ERROR' })) `
                ("RequirePlatformSecurityFeatures: {0} -> {1}" -f $rpsfText, $postText) $why $true
            Write-Log ("R1b unmeetable prerequisite removed ({0} -> {1}); VBS/HVCI will be able to start after reboot" -f $rpsfText, $postText) 'FIX'
        } catch {
            Add-StepResult 'R1b' 'Unblock the startup of VBS/HVCI' $true 'ERROR' "current=$rpsfText" $_.Exception.Message
            Write-Log "R1b ERROR $($_.Exception.Message)" 'ERROR'
        }
    } else {
        Add-StepResult 'R1b' 'Unblock the startup of VBS/HVCI' $true 'WOULD_FIX' "current=$rpsfText" ("{0}. Action: {1}" -f $why, $act) $true
        Write-Log "R1b [dry-run] $act" 'WOULD'
    }
}

# ====================================================================================================
# R2 - Re-enable HVCI / Memory integrity (registry)  [requires reboot]
# ====================================================================================================
$enHvci = Get-RegDword $hvciKey 'Enabled'
$needR2 = ($enHvci -ne 1)
if (-not $needR2) {
    Add-StepResult 'R2' 'HVCI enabled (registry)' $false 'OK' "Enabled=$enHvci" 'Already at 1'
    Write-Log 'R2 HVCI already enabled in registry' 'OK'
} else {
    if (Confirm-Change "$hvciKey\Enabled" 'Set 1' -Id 'R2') {
        try {
            Set-RegDword $hvciKey 'Enabled' 1
            $post = Get-RegDword $hvciKey 'Enabled'
            Add-StepResult 'R2' 'HVCI enabled (registry)' $true 'FIXED' "-> $post" 'Requires a reboot' $true
            Write-Log 'R2 HVCI enabled (reboot required)' 'FIX'
        } catch { Add-StepResult 'R2' 'HVCI enabled (registry)' $true 'ERROR' '' $_.Exception.Message; Write-Log "R2 ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R2' 'HVCI enabled (registry)' $true 'WOULD_FIX' "current=$enHvci" 'Would set HVCI Enabled=1 (reboot)' $true
        Write-Log 'R2 [dry-run] would enable HVCI in registry' 'WOULD'
    }
}

# ====================================================================================================
# R3 - testsigning OFF (BCD)  [requires reboot]
# ====================================================================================================
$ts = Get-BcdValue 'testsigning'
$needR3 = ($ts -and $ts -match '^(Yes|On|1|true)$')
if (-not $needR3) {
    Add-StepResult 'R3' 'testsigning OFF' $false 'OK' ("testsigning={0}" -f ($(if($ts){$ts}else{'No'}))) 'DSE not weakened'
    Write-Log 'R3 testsigning already OFF' 'OK'
} else {
    if (Confirm-Change 'BCD {current}' 'bcdedit /set testsigning off' -Id 'R3') {
        try {
            & bcdedit /set testsigning off | Out-Null
            $post = Get-BcdValue 'testsigning'
            $ok = (-not $post -or $post -match '^(No|Off|0)$')
            Add-StepResult 'R3' 'testsigning OFF' $true ($(if($ok){'FIXED'}else{'ERROR'})) "-> $post" 'Requires a reboot' $true
            Write-Log "R3 testsigning off (reboot required)" 'FIX'
        } catch { Add-StepResult 'R3' 'testsigning OFF' $true 'ERROR' '' $_.Exception.Message; Write-Log "R3 ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R3' 'testsigning OFF' $true 'WOULD_FIX' "current=$ts" 'Would run: bcdedit /set testsigning off (reboot)' $true
        Write-Log 'R3 [dry-run] would set testsigning off' 'WOULD'
    }
}

# ====================================================================================================
# R3b - nointegritychecks OFF (BCD)  [another way to weaken DSE]  [requires reboot]
# ====================================================================================================
$ni = Get-BcdValue 'nointegritychecks'
$needR3b = ($ni -and $ni -match '^(Yes|On|1|true)$')
if (-not $needR3b) {
    Add-StepResult 'R3b' 'nointegritychecks OFF' $false 'OK' ("nointegritychecks={0}" -f ($(if($ni){$ni}else{'No'}))) 'DSE not weakened via this route'
    Write-Log 'R3b nointegritychecks already OFF' 'OK'
} else {
    if (Confirm-Change 'BCD {current}' 'bcdedit /set nointegritychecks off' -Id 'R3b') {
        try {
            & bcdedit /set nointegritychecks off | Out-Null
            $post = Get-BcdValue 'nointegritychecks'
            $ok = (-not $post -or $post -match '^(No|Off|0)$')
            Add-StepResult 'R3b' 'nointegritychecks OFF' $true ($(if($ok){'FIXED'}else{'ERROR'})) "-> $post" 'Requires a reboot' $true
            Write-Log 'R3b nointegritychecks off (reboot required)' 'FIX'
        } catch { Add-StepResult 'R3b' 'nointegritychecks OFF' $true 'ERROR' '' $_.Exception.Message; Write-Log "R3b ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R3b' 'nointegritychecks OFF' $true 'WOULD_FIX' "current=$ni" 'Would run: bcdedit /set nointegritychecks off (reboot)' $true
        Write-Log 'R3b [dry-run] would set nointegritychecks off' 'WOULD'
    }
}

# ====================================================================================================
# R4 - hypervisorlaunchtype = Auto (so VBS can start)  [requires reboot]
# ====================================================================================================
$hlt = Get-BcdValue 'hypervisorlaunchtype'
$needR4 = ($hlt -and $hlt -match '^(Off)$')
if (-not $needR4) {
    Add-StepResult 'R4' 'hypervisorlaunchtype=Auto' $false 'OK' ("hlt={0}" -f ($(if($hlt){$hlt}else{'(default)'}))) 'The VBS hypervisor can start'
    Write-Log 'R4 hypervisorlaunchtype is not Off' 'OK'
} else {
    if (Confirm-Change 'BCD {current}' 'bcdedit /set hypervisorlaunchtype Auto' -Id 'R4') {
        try {
            & bcdedit /set hypervisorlaunchtype Auto | Out-Null
            $post = Get-BcdValue 'hypervisorlaunchtype'
            Add-StepResult 'R4' 'hypervisorlaunchtype=Auto' $true 'FIXED' "-> $post" 'Requires a reboot' $true
            Write-Log 'R4 hypervisorlaunchtype=Auto (reboot required)' 'FIX'
        } catch { Add-StepResult 'R4' 'hypervisorlaunchtype=Auto' $true 'ERROR' '' $_.Exception.Message; Write-Log "R4 ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R4' 'hypervisorlaunchtype=Auto' $true 'WOULD_FIX' "current=$hlt" 'Would run: bcdedit /set hypervisorlaunchtype Auto (reboot)' $true
        Write-Log 'R4 [dry-run] would set hypervisorlaunchtype=Auto' 'WOULD'
    }
}

# ====================================================================================================
# R5 - Remove the IOC key HKLM\SOFTWARE\ManageVBS
# ====================================================================================================
$mvbs = 'HKLM:\SOFTWARE\ManageVBS'
$needR5 = Test-Path $mvbs
if (-not $needR5) {
    Add-StepResult 'R5' 'Clean up ManageVBS IOC' $false 'OK' 'absent' 'No leftover from the technique'
    Write-Log 'R5 ManageVBS absent' 'OK'
} else {
    if (Confirm-Change $mvbs 'Remove-Item -Recurse' -Id 'R5') {
        try {
            Remove-Item -Path $mvbs -Recurse -Force
            $ok = -not (Test-Path $mvbs)
            Add-StepResult 'R5' 'Clean up ManageVBS IOC' $true ($(if($ok){'FIXED'}else{'ERROR'})) 'removed' 'Tracking key left by VBS.cmd'
            Write-Log 'R5 ManageVBS removed' 'FIX'
        } catch { Add-StepResult 'R5' 'Clean up ManageVBS IOC' $true 'ERROR' '' $_.Exception.Message; Write-Log "R5 ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R5' 'Clean up ManageVBS IOC' $true 'WOULD_FIX' 'present' 'Would remove HKLM\SOFTWARE\ManageVBS'
        Write-Log 'R5 [dry-run] would remove ManageVBS' 'WOULD'
    }
}

# ====================================================================================================
# R6 - Unregister the RESIDUAL bypass driver (allowlist; only if it is NOT running)
# ====================================================================================================
$allow = @('simplesvm','hyperkd','hyperhv','hyperevade')
$residual = @()
try {
    $residual = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
        Where-Object { $n = $_.Name.ToLower(); $allow | Where-Object { $n -like "*$_*" } })
} catch {}
if ($residual.Count -eq 0) {
    Add-StepResult 'R6' 'Residual bypass driver' $false 'OK' 'none registered' 'Nothing to unregister'
    Write-Log 'R6 no bypass driver registered' 'OK'
} else {
    foreach ($d in $residual) {
        if ($d.State -eq 'Running') {
            Add-StepResult 'R6' ("Residual driver: {0}" -f $d.Name) $true 'MANUAL' "State=Running; Path=$($d.PathName)" 'RUNNING: deletion is not forced (BSOD risk). Reboot to unload it, then run T5 again.' $false $true
            Write-Log "R6 $($d.Name) RUNNING -> left untouched; reboot first" 'MANUAL'
            continue
        }
        # By default: QUARANTINE (disable startup, without deleting the file) -> safer and reversible.
        # With -RemoveResidualDriver: unregister the service (sc delete).
        $act = if ($RemoveResidualDriver) { 'sc.exe delete' } else { 'sc.exe config start=disabled (quarantine)' }
        if (Confirm-Change $d.Name $act -Id 'R6') {
            try {
                if ($RemoveResidualDriver) {
                    & sc.exe delete $d.Name | Out-Null
                    Add-StepResult 'R6' ("Residual driver: {0}" -f $d.Name) $true 'FIXED' "sc delete (exit $LASTEXITCODE)" 'Driver service unregistered'
                    Write-Log "R6 $($d.Name) unregistered (sc delete)" 'FIX'
                } else {
                    & sc.exe config $d.Name start= disabled | Out-Null
                    Add-StepResult 'R6' ("Residual driver: {0}" -f $d.Name) $true 'FIXED' "start=disabled (exit $LASTEXITCODE)" 'Driver in QUARANTINE (will not start; file left intact). Use -RemoveResidualDriver to delete it.'
                    Write-Log "R6 $($d.Name) quarantined (start=disabled)" 'FIX'
                }
            } catch { Add-StepResult 'R6' ("Residual driver: {0}" -f $d.Name) $true 'ERROR' '' $_.Exception.Message; Write-Log "R6 ERROR $($_.Exception.Message)" 'ERROR' }
        } else {
            Add-StepResult 'R6' ("Residual driver: {0}" -f $d.Name) $true 'WOULD_FIX' "State=$($d.State)" ("Would run: $act")
            Write-Log "R6 [dry-run] $act on $($d.Name)" 'WOULD'
        }
    }
}

# ====================================================================================================
# R7 - Secure Boot (CANNOT be done from the OS -> manual guidance)
# ====================================================================================================
$sbOn = $null
try { $sbOn = Confirm-SecureBootUEFI } catch { $sbOn = $null }
if ($sbOn -eq $true) {
    Add-StepResult 'R7' 'Secure Boot ON' $false 'OK' 'Enabled' 'Boot chain verified'
    Write-Log 'R7 Secure Boot already ON' 'OK'
} else {
    $obs = if ($null -eq $sbOn) { 'not determinable / legacy BIOS' } else { 'Disabled' }
    # Secure Boot CANNOT be turned on from the OS: the UEFI 'SecureBoot' variable is read-only at
    # runtime, and the switch lives in firmware (usually requires physical presence). Neither the
    # crack nor this tool can restore it: they can only GUIDE the user. Both real side effects are
    # flagged below.
    $bl = ''
    try {
        $blv = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { "$($_.ProtectionStatus)" -ne 'Off' })
        if ($blv.Count -gt 0) {
            $bl = ' BITLOCKER WARNING: you have active encryption on ' + (($blv | ForEach-Object { $_.MountPoint }) -join ',') +
                  '. Changing Secure Boot alters the boot measurements (PCR 7), and Windows may ask for the RECOVERY KEY on reboot:' +
                  ' save it BEFOREHAND (Microsoft Account / "Back up your recovery key"), or suspend BitLocker for one reboot.'
        }
    } catch { }
    $guide = 'How to enable it (a FIRMWARE step, cannot be done from Windows): (1) shortcut straight into firmware:' +
             ' run as admin  shutdown /r /fw /t 0  (or Settings > System > Recovery > Advanced startup >' +
             ' Troubleshoot > Advanced options > UEFI Firmware Settings). (2) In UEFI look for Security/Boot >' +
             ' Secure Boot > Enabled (Standard mode). If it is greyed out, first set a supervisor password and/or' +
             ' switch the boot mode to UEFI (not Legacy/CSM). (3) Save and reboot. (4) Go back to "Check" to validate.' +
             ' IMPORTANT: if you boot another OS (Linux) with unsigned modules, Secure Boot may block that boot.' +
             ' NOTE: HVCI does NOT need Secure Boot to protect you; if Secure Boot stays OFF, HVCI can still run (see R1b).' + $bl
    Add-StepResult 'R7' 'Secure Boot ON' $true 'MANUAL' $obs $guide $false $true
    Write-Log "R7 Secure Boot ($obs) -> MANUAL step in UEFI" 'MANUAL'
}

# ====================================================================================================
# R8 - Microsoft Vulnerable Driver Blocklist (anti-BYOVD)  [requires reboot]
# ====================================================================================================
$ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$vdb = Get-RegDword $ciKey 'VulnerableDriverBlocklistEnable'
$needR8 = ($vdb -ne 1)
if (-not $needR8) {
    Add-StepResult 'R8' 'Vulnerable Driver Blocklist' $false 'OK' "VulnerableDriverBlocklistEnable=$vdb" 'Vulnerable driver blocklist (BYOVD) active'
    Write-Log 'R8 blocklist already active' 'OK'
} else {
    if (Confirm-Change "$ciKey\VulnerableDriverBlocklistEnable" 'Set 1' -Id 'R8') {
        try {
            Set-RegDword $ciKey 'VulnerableDriverBlocklistEnable' 1
            $post = Get-RegDword $ciKey 'VulnerableDriverBlocklistEnable'
            Add-StepResult 'R8' 'Vulnerable Driver Blocklist' $true 'FIXED' "-> $post" 'Requires a reboot' $true
            Write-Log 'R8 blocklist enabled (reboot required)' 'FIX'
        } catch { Add-StepResult 'R8' 'Vulnerable Driver Blocklist' $true 'ERROR' '' $_.Exception.Message; Write-Log "R8 ERROR $($_.Exception.Message)" 'ERROR' }
    } else {
        Add-StepResult 'R8' 'Vulnerable Driver Blocklist' $true 'WOULD_FIX' "current=$vdb" 'Would set VulnerableDriverBlocklistEnable=1 (reboot)' $true
        Write-Log 'R8 [dry-run] would enable the blocklist' 'WOULD'
    }
}

# ====================================================================================================
# R9 - Clean up residual crack IOC files on disk (same list as T0/D5)
# ====================================================================================================
$IocFileNames = @(
    'SimpleSvm.sys','hyperkd.sys','hyperhv.dll','hyperevade.dll','hypervisor-launcher.exe',
    'VBS.cmd','DenuvOwO.nfo','DenuoOwO_SRC.7z','EfiGuardDxe.efi','Loader.efi'
)
$iocRoots = @()
foreach ($p in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:ProgramData")) {
    if ($p -and (Test-Path $p)) { $iocRoots += $p }
}
$iocHits = @()
foreach ($root in $iocRoots) {
    try {
        $iocHits += @(Get-ChildItem -Path $root -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue |
                       Where-Object { $IocFileNames -contains $_.Name })
    } catch { }
}
if ($iocHits.Count -eq 0) {
    Add-StepResult 'R9' 'Clean up residual IOC files' $false 'OK' '0 IOC files' ("Scanned paths: {0}" -f ($iocRoots -join '; '))
    Write-Log 'R9 no residual IOC files' 'OK'
} else {
    foreach ($f in ($iocHits | Sort-Object FullName -Unique)) {
        $fPath = $f.FullName
        $parentDir = $f.DirectoryName
        if (Confirm-Change $fPath 'Remove-Item (residual IOC file)' -Id 'R9') {
            try {
                Remove-Item -LiteralPath $fPath -Force -ErrorAction Stop
                $parentEmpty = $false
                try { $parentEmpty = (@(Get-ChildItem -LiteralPath $parentDir -Force -ErrorAction SilentlyContinue).Count -eq 0) } catch { }
                if ($parentEmpty -and $parentDir -match '[\\/]\.tmp[A-Za-z0-9]+$') {
                    try { Remove-Item -LiteralPath $parentDir -Force -ErrorAction SilentlyContinue } catch { }
                }
                Add-StepResult 'R9' ("IOC removed: {0}" -f $f.Name) $true 'FIXED' $fPath 'Residual crack file deleted'
                Write-Log "R9 removed: $fPath" 'FIX'
            } catch {
                Add-StepResult 'R9' ("IOC file: {0}" -f $f.Name) $true 'ERROR' $fPath $_.Exception.Message
                Write-Log "R9 ERROR deleting $fPath : $($_.Exception.Message)" 'ERROR'
            }
        } else {
            Add-StepResult 'R9' ("IOC file: {0}" -f $f.Name) $true 'WOULD_FIX' $fPath 'Would delete this residual crack file'
            Write-Log "R9 [dry-run] would delete $fPath" 'WOULD'
        }
    }
}

# ====================================================================================================
# Verdict
# ====================================================================================================
$needed  = @($Steps | Where-Object { $_.needed })
$errors  = @($Steps | Where-Object { $_.status -eq 'ERROR' })
$pending = @($Steps | Where-Object { $_.status -in @('WOULD_FIX') })            # dry-run: action not applied
$skipped = @($Steps | Where-Object { $_.status -eq 'SKIPPED' })                 # the user did not choose it
$reboot  = @($Steps | Where-Object { $_.rebootRequired -and $_.status -eq 'FIXED' })
$manual  = @($Steps | Where-Object { $_.manual -and $_.needed })

if ($errors.Count -gt 0) { $overall = 'ERRORS'; $exit = 2 }
elseif ($pending.Count -gt 0) { $overall = 'ACTIONS PENDING (dry-run)'; $exit = 1 }
elseif ($reboot.Count -gt 0 -or $manual.Count -gt 0) { $overall = 'APPLIED - REBOOT/UEFI PENDING'; $exit = 1 }
elseif ($skipped.Count -gt 0) { $overall = 'PARTIALLY APPLIED (by user choice)'; $exit = 1 }
elseif ($needed.Count -eq 0) { $overall = 'SYSTEM HEALTHY'; $exit = 0 }
else { $overall = 'REMEDIATED'; $exit = 0 }

$result = [ordered]@{
    tool='T5-remediation'; version='1.1.0'
    mode=$(if ($Apply) {'apply'} else {'dry-run'})
    timestampUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname=$env:COMPUTERNAME; elevated=$IsElevated
    overall=$overall; exitCode=$exit
    rebootRequired=($reboot.Count -gt 0); manualStepsPending=($manual.Count -gt 0)
    selectionApplied=$HasFilter
    selectedIds=@($SelectedSet.Keys)
    skippedCount=$skipped.Count
    steps=@($Steps)
}
$json = ($result | ConvertTo-Json -Depth 6)
if ($JsonPath) { try { $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force } catch { Write-Warning "JSON: $($_.Exception.Message)" } }

if ($AsJson) { Write-Output $json }
elseif (-not $Quiet) {
    Write-Host ''
    Write-Host ("=== T5 remediation - VERDICT: {0} (exit {1}) ===" -f $overall, $exit) -ForegroundColor Cyan
    if (-not $Apply -and $pending.Count -gt 0) { Write-Host 'DRY-RUN: nothing has been changed. Review the output above and run with -Apply to remediate.' -ForegroundColor Yellow }
    if ($reboot.Count -gt 0) { Write-Host 'REBOOT REQUIRED for VBS/HVCI/testsigning to take effect.' -ForegroundColor Yellow }
    if ($manual.Count -gt 0) { Write-Host 'MANUAL STEPS pending (Secure Boot in UEFI and/or a running driver -> reboot).' -ForegroundColor Cyan }
    if ($skipped.Count -gt 0) { Write-Host ("NOT APPLIED BY YOUR CHOICE: {0} step(s) -> {1}" -f $skipped.Count, (($skipped | ForEach-Object { $_.id }) -join ', ')) -ForegroundColor DarkYellow }
    Write-Host 'After remediating and rebooting: validate with T1-posture-check.ps1 and harden further with T2 (HVCI) + T3 (WDAC).' -ForegroundColor DarkGray
    Write-Host ''
}
exit $exit
