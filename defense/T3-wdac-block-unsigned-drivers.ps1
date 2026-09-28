#Requires -Version 5.1
<#
.SYNOPSIS
    T3 - WDAC (Windows Defender Application Control) policy that blocks loading UNSIGNED drivers
    -- exactly what the bypass technique needs to inject (SimpleSvm.sys / hyperkd.sys). With HVCI
    active, the block is enforced by the hypervisor (VTL1).

.DESCRIPTION
    Generates and deploys a WDAC policy from the OFFICIAL Windows templates
    (C:\Windows\schemas\CodeIntegrity\ExamplePolicies), which require signed code (Microsoft/WHQL) and
    therefore block unsigned drivers. It also merges Microsoft's recommended vulnerable driver
    blocklist if available.

    ⚠️  SECURITY: a badly-tuned WDAC policy can prevent BOOTING. Because of this:
        - By default it deploys in AUDIT MODE (-Audit): it does NOT block; it only logs to
          Microsoft-Windows-CodeIntegrity/Operational (events 3076/3077) what would be blocked.
        - Only -Enforce switches to real blocking. Do this ONLY after reviewing the audit events and
          ONLY on a VM with a snapshot first.
        - -Remove reverts it (deletes the deployed policy).
    This tool NEVER relaxes code integrity; it only strengthens it.

.PARAMETER Audit     Deploys in audit mode (default if -Enforce is not given).
.PARAMETER Enforce   Deploys in blocking mode (enforced). Requires having audited first.
.PARAMETER Remove    Removes the deployed policy (rollback).
.PARAMETER Status    Shows status (default if no action is given).
.PARAMETER OutDir    Working folder for the .xml/.cip files (def. C:\ProgramData\HVGuard\WDAC).
.PARAMETER Force     Does not ask for confirmation.

.OUTPUTS
    Exit: 0 = OK/status | 1 = action pending/reboot recommended | 2 = error.

.NOTES
    Doc 04 T3. Requires Administrator and Win10 1903+/Win11. Pair with HVCI (T2) and telemetry (T4:
    watch CodeIntegrity 3033/3077). Test on a VM with snapshots BEFORE touching a real machine.
    Version: 1.1.0 (kernel-only: no UMCI; own policy GUID; -Remove finds policies by name)
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Audit,
    [switch]$Enforce,
    [switch]$Remove,
    [switch]$Status,
    [string]$OutDir = "$env:ProgramData\HVGuard\WDAC",
    [switch]$Force,
    [switch]$AsJson,
    [string]$JsonPath,
    [switch]$Quiet
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$onWindows = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }
if (-not $onWindows) { Write-Error 'T3 only applies to Windows.'; exit 2 }
$IsElevated = $false
try { $IsElevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}

# Default action
if (-not ($Audit -or $Enforce -or $Remove -or $Status)) { $Status = $true }
if (($Enforce -or $Audit -or $Remove) -and -not $IsElevated) { Write-Error 'Requires Administrator to deploy/remove WDAC.'; exit 2 }

$log = [System.Collections.Generic.List[object]]::new()
function Note($id,$name,$status,$evidence){ $log.Add([pscustomobject]@{id=$id;name=$name;status=$status;evidence=$evidence}) }
function DoIt($target,$act){ if ($Force) { return $true } return $PSCmdlet.ShouldProcess($target,$act) }

$examples = "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies"
$policyName = 'HVGuard-BlockUnsignedDrivers'
$xml  = Join-Path $OutDir "$policyName.xml"
$cip  = Join-Path $OutDir "$policyName.cip"

# Our own fixed policy GUID, written into <PolicyID>/<BasePolicyID> so it can be updated/removed.
# (T3 < 1.1.0 only set it as a text label, so the policy kept the Microsoft template GUID.)
$PolicyId = '{9A7F2B19-4C3E-4F8A-B1D2-A1B2C3D4E5F6}'

function Get-CiToolPath { $p = "$env:SystemRoot\System32\CiTool.exe"; if (Test-Path $p) { return $p } return $null }
function Format-HvgGuid($g) { '{' + ("$g".Trim('{}')).ToUpperInvariant() + '}' }

# --json also suppresses CiTool's "press Enter to continue" prompt.
function Invoke-HvgCiTool([string[]]$CiArgs) {
    $out = (& (Get-CiToolPath) @CiArgs --json 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $obj = $null
    try { $obj = $out | ConvertFrom-Json -ErrorAction Stop } catch {}
    if ($obj -and $obj.PSObject.Properties['OperationResult']) { $code = [int64]$obj.OperationResult }
    if ($code -ne 0) { throw ("CiTool {0} failed (0x{1:X}): {2}" -f ($CiArgs -join ' '), $code, $out.Trim()) }
    return $obj
}

# Policies deployed by any T3 version (old ones carry the template GUID), matched by name.
function Get-HvgPolicies {
    $o = Invoke-HvgCiTool @('--list-policies')
    if (-not $o -or -not $o.PSObject.Properties['Policies']) { return @() }
    return @($o.Policies | Where-Object { $_.FriendlyName -eq $policyName -and -not $_.IsSystemPolicy })
}

# --------------------------------------------------------------------------------------------------
# STATUS
# --------------------------------------------------------------------------------------------------
if ($Status) {
    $citool = Get-CiToolPath
    $hvci = 'unknown'
    try { $d = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
          $run=@(); if($d.SecurityServicesRunning){$run=@($d.SecurityServicesRunning|%{[int]$_})}; $hvci = $(if($run -contains 2){'running'}else{'not running'}) } catch {}
    Note 'STATUS' 'WDAC/HVCI' 'INFO' ("CiTool={0}; HVCI={1}; policy deployed at {2}" -f [bool]$citool,$hvci,$xml)
    if ($citool) {
        try {
            $mine = @(Get-HvgPolicies)
            if (-not $mine.Count) { Note 'POLICY' 'HVGuard policy' 'INFO' 'not deployed' }
            foreach ($p in $mine) {
                $opts = @($p.PolicyOptions)
                $pmode = if ($opts -contains 'Enabled:Audit Mode') { 'audit' } else { 'enforce' }
                Note 'POLICY' 'HVGuard policy' 'INFO' ("{0} v{1} ({2})" -f (Format-HvgGuid $p.PolicyID), $p.VersionString, $pmode)
                if ($opts -contains 'Enabled:UMCI') {
                    Note 'UMCI' 'User-mode rules' 'WARN' 'Enabled:UMCI present (deployed by T3 < 1.1.0): PowerShell 7 reports ConstrainedLanguage. Re-run -Audit to migrate.'
                }
            }
        } catch { Note 'POLICY' 'HVGuard policy' 'INFO' ("could not list policies (run as Administrator): {0}" -f $_.Exception.Message) }
    }
    if (-not $Quiet -and -not $AsJson) {
        Write-Host "`n=== T3 WDAC - status ===" -ForegroundColor Cyan
        Write-Host ("HVCI: {0}" -f $hvci)
        foreach ($a in @($log | Where-Object { $_.id -in 'POLICY','UMCI' })) {
            Write-Host ("  {0,-5} {1}" -f $a.status, $a.evidence) -ForegroundColor $(if ($a.status -eq 'WARN') { 'Yellow' } else { 'Gray' })
        }
        if (-not $citool) { Write-Host 'CiTool.exe not present (older Win10): deploying via legacy method.' -ForegroundColor Yellow }
        Write-Host 'To deploy: -Audit (safe) -> review CodeIntegrity events 3076/3077 -> -Enforce.' -ForegroundColor DarkGray
    }
}

# --------------------------------------------------------------------------------------------------
# BUILD + DEPLOY  (Audit / Enforce)
# --------------------------------------------------------------------------------------------------
if ($Audit -or $Enforce) {
    $mode = if ($Enforce) { 'ENFORCED' } else { 'AUDIT' }
    if (DoIt $policyName "Build and deploy WDAC ($mode)") {
        try {
            if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }

            # Base: official template that requires signed code (blocks unsigned).
            $base = $null
            foreach ($cand in @('DefaultWindows_Audit.xml','AllowMicrosoft.xml','DefaultWindows_Enforced.xml')) {
                if (Test-Path (Join-Path $examples $cand)) { $base = Join-Path $examples $cand; break }
            }
            if (-not $base) { throw "Cannot find WDAC templates in $examples (requires Win10 1903+/Win11)." }
            Copy-Item $base $xml -Force
            Note 'BASE' 'Base template' 'OK' (Split-Path $base -Leaf)

            # Merges (OPTIONAL, NOT FATAL) Microsoft's vulnerable driver blocklist. If it fails (e.g.
            # "Access denied" reading the protected .xml), a warning is shown and execution continues: the
            # base policy already requires signing and blocks unsigned drivers on its own.
            $blk = Join-Path $examples 'RecommendedDriverBlock_Enforced.xml'
            if (Test-Path $blk) {
                try {
                    $blkLocal = Join-Path $OutDir 'RecoDriverBlock.xml'
                    Copy-Item $blk $blkLocal -Force -ErrorAction Stop
                    $merged = Join-Path $OutDir 'merged.xml'
                    Merge-CIPolicy -PolicyPaths $xml,$blkLocal -OutputFilePath $merged -ErrorAction Stop | Out-Null
                    Copy-Item $merged $xml -Force
                    Note 'BLK' 'MS driver blocklist' 'OK' 'merged'
                } catch {
                    Note 'BLK' 'MS driver blocklist' 'WARN' ("not merged (not critical; the base already requires signing): {0}" -f $_.Exception.Message)
                }
            } else {
                Note 'BLK' 'MS driver blocklist' 'WARN' 'not present; the base policy already blocks unsigned drivers'
            }

            # Rule options. Key for "block unsigned drivers": do NOT enable "unsigned" rules;
            # keep the signing requirement in place. Audit vs Enforce = option 3.
            # Kernel-only policy: UMCI (option 0) would put PowerShell 7 in ConstrainedLanguage and, enforced,
            # block every non-Microsoft user-mode app.
            Set-RuleOption -FilePath $xml -Option 0 -Delete
            Set-RuleOption -FilePath $xml -Option 2 -Delete    # removes "Required:WHQL" if present (avoids initial over-blocking)
            Set-RuleOption -FilePath $xml -Option 6            # Enabled:Unsigned System Integrity Policy (allows signing the policy itself later)
            if ($Audit)   { Set-RuleOption -FilePath $xml -Option 3 }          # Enabled:Audit Mode
            if ($Enforce) { Set-RuleOption -FilePath $xml -Option 3 -Delete }  # removes Audit -> enforced
            Set-CIPolicyIdInfo -FilePath $xml -PolicyName $policyName -PolicyId $PolicyId | Out-Null
            [xml]$px = Get-Content -LiteralPath $xml -Raw
            $px.SiPolicy.PolicyID = $PolicyId
            $px.SiPolicy.BasePolicyID = $PolicyId
            $px.Save($xml)

            # Never go below an already deployed version.
            $citool = Get-CiToolPath
            $existing = @(); if ($citool) { $existing = @(Get-HvgPolicies) }
            $ver = [version]'1.0.0.0'
            foreach ($p in $existing) {
                $v = [version]$p.VersionString
                if ($v -ge $ver) { $ver = [version]::new($v.Major, $v.Minor, $v.Build, $v.Revision + 1) }
            }
            Set-CIPolicyVersion -FilePath $xml -Version $ver.ToString()

            # Compile .cip
            ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cip | Out-Null
            Note 'BUILD' 'Compile policy' 'OK' ("{0} ({1} v{2})" -f $cip, $PolicyId, $ver)

            # Deployment: CiTool (Win11 22H2+) preferred; otherwise, legacy method + refresh.
            if ($citool) {
                Invoke-HvgCiTool @('--update-policy', $cip) | Out-Null
                Note 'DEPLOY' "Deploy ($mode)" 'APPLIED' 'CiTool --update-policy (activates without reboot; full effect after reboot)'
                foreach ($old in @($existing | Where-Object { (Format-HvgGuid $_.PolicyID) -ne $PolicyId })) {
                    $og = Format-HvgGuid $old.PolicyID
                    Invoke-HvgCiTool @('--remove-policy', $og) | Out-Null
                    Note 'MIGRATE' 'Old policy removed' 'APPLIED' "$og (v$($old.VersionString))"
                }
                $now = @(Get-HvgPolicies | Where-Object { (Format-HvgGuid $_.PolicyID) -eq $PolicyId })
                if (-not $now.Count) { throw "CiTool does not list $PolicyId after deploying it" }
                if (@($now[0].PolicyOptions) -contains 'Enabled:UMCI') { throw "$PolicyId still has Enabled:UMCI" }
                Note 'VERIFY' 'Deployed policy' 'OK' ("{0} v{1}, no UMCI" -f $PolicyId, $now[0].VersionString)
            } else {
                $dest = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
                if (-not (Test-Path $dest)) { New-Item -Path $dest -ItemType Directory -Force | Out-Null }
                Copy-Item $cip (Join-Path $dest "$PolicyId.cip") -Force
                Note 'DEPLOY' "Deploy ($mode)" 'APPLIED' 'copied to CiPolicies\Active; REBOOT required'
            }
            if ($Enforce -and -not $Quiet) { Write-Warning 'ENFORCED MODE: verify that NOTHING critical was left blocked in the prior audit.' }
        } catch { Note 'DEPLOY' "Deploy ($mode)" 'ERROR' $_.Exception.Message }
    } else { Note 'DEPLOY' "Deploy ($(if($Enforce){'ENFORCED'}else{'AUDIT'}))" 'WOULD' "Would build and deploy $policyName" }
}

# --------------------------------------------------------------------------------------------------
# REMOVE (rollback)
# --------------------------------------------------------------------------------------------------
if ($Remove) {
    if (DoIt $policyName 'Remove WDAC policy') {
        try {
            $citool = Get-CiToolPath
            if ($citool) {
                $mine = @(Get-HvgPolicies)
                if (-not $mine.Count) { throw "no $policyName policy is deployed" }
                foreach ($p in $mine) {
                    $g = Format-HvgGuid $p.PolicyID
                    Invoke-HvgCiTool @('--remove-policy', $g) | Out-Null
                    Note 'REMOVE' 'Rollback' 'APPLIED' "CiTool --remove-policy $g"
                }
            } else {
                $f = Join-Path "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" "$PolicyId.cip"
                if (-not (Test-Path -LiteralPath $f)) { throw "not found: $f" }
                Remove-Item -LiteralPath $f -Force
                Note 'REMOVE' 'Rollback' 'APPLIED' '.cip file removed; REBOOT required'
            }
        } catch { Note 'REMOVE' 'Rollback' 'ERROR' $_.Exception.Message }
    } else { Note 'REMOVE' 'Rollback' 'WOULD' 'Would remove the deployed policy' }
}

# --------------------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------------------
$err = @($log | Where-Object { $_.status -eq 'ERROR' })
$would = @($log | Where-Object { $_.status -eq 'WOULD' })
if ($err.Count) { $overall='ERROR'; $exit=2 } elseif ($would.Count) { $overall='PENDING'; $exit=1 } else { $overall='OK'; $exit=0 }
$result=[ordered]@{ tool='T3-wdac-block-unsigned-drivers'; version='1.1.0'
    timestampUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); hostname=$env:COMPUTERNAME
    elevated=$IsElevated; mode=$(if($Enforce){'enforce'}elseif($Audit){'audit'}elseif($Remove){'remove'}else{'status'})
    overall=$overall; exitCode=$exit; log=@($log) }
$json=$result|ConvertTo-Json -Depth 6
if ($JsonPath){ try{$json|Out-File -FilePath $JsonPath -Encoding utf8 -Force}catch{} }
if ($AsJson){ Write-Output $json }
elseif (-not $Quiet -and -not $Status){
    Write-Host "`n=== T3 WDAC - $overall (exit $exit) ===" -ForegroundColor Cyan
    foreach($a in $log){ $c=switch($a.status){'APPLIED'{'Green'}'OK'{'Green'}'WOULD'{'Yellow'}'WARN'{'Yellow'}'ERROR'{'Red'}default{'Gray'}}
        Write-Host ("  {0,-8} {1,-22} {2}" -f $a.status,$a.name,$a.evidence) -ForegroundColor $c }
    Write-Host 'Safe flow: -Audit -> review CodeIntegrity 3076/3077 -> -Enforce. Rollback: -Remove.' -ForegroundColor DarkGray; Write-Host ''
}
exit $exit
