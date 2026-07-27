# =====================================================================================================
#  HVGuard - lib/Engine.ps1
#  Engine <-> GUI bridge. Invokes the defense/ .ps1 scripts (T0..T5, T7) as a CHILD PROCESS and reads
#  their JSON output. Does NOT reimplement the engine's logic nor interpret verdicts: it only runs
#  them, collects the exit code and deserializes the JSON. Designed to NEVER crash the GUI (everything
#  goes through try/catch and returns a uniform result object).
#
#  Contract of the engine scripts (verified in defense/): they accept -AsJson, -JsonPath <file>,
#  -Quiet and return exit codes 0/1/2. They write the JSON to -JsonPath as well as to STDOUT with -AsJson.
#
#  Execution: two paths over the same child-process engine:
#    - Invoke-HvgTool        -> SYNCHRONOUS (blocks; for short calls or console scripts).
#    - Start-HvgTool/Complete-HvgTool -> primitives for the ASYNCHRONOUS path (see UI.ps1 Invoke-HvgToolAsync),
#      which does NOT block the UI thread: the heavy work already lives in the child process; the GUI just polls.
#
#  Compatibility: Windows PowerShell 5.1 (.NET Framework) and PowerShell 7 (.NET). That is why
#  [Type]::new() is used (not New-Object for generics) and the command line is built by hand
#  (ProcessStartInfo.ArgumentList does not exist in 5.1). Set-StrictMode/ErrorActionPreference is NOT
#  set globally here: this file is dot-sourced inside the GUI and a global 'Stop' could bring down the
#  WPF dispatcher. Each function handles its own errors.
# =====================================================================================================

# --- Repo and engine location --------------------------------------------------------------------------
$script:HvgLibDir      = $PSScriptRoot
$script:HvgLauncherDir = Split-Path -Parent $PSScriptRoot
$script:HvgRoot        = Split-Path -Parent $script:HvgLauncherDir

$script:HvgDefenseDirs = @(
    (Join-Path $script:HvgRoot        'defense'),
    (Join-Path $script:HvgLauncherDir 'defense'),
    (Join-Path $script:HvgLibDir      'defense')
) | Where-Object { $_ }

$script:HvgHostExe = $null
try { $script:HvgHostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch { }
if (-not $script:HvgHostExe) {
    $cand = Join-Path $PSHOME (if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' })
    if (Test-Path $cand) { $script:HvgHostExe = $cand } else { $script:HvgHostExe = 'powershell.exe' }
}

$script:HvgScriptMap = @{
    T0 = 'T0-hv-detector.ps1'
    T1 = 'T1-posture-check.ps1'
    T2 = 'T2-hvci-enforce-monitor.ps1'
    T3 = 'T3-wdac-block-unsigned-drivers.ps1'
    T5 = 'T5-remediation.ps1'
    T7 = 'T7-target-scan.ps1'
}

# =====================================================================================================
#  Environment utilities
# =====================================================================================================
function Get-HvgRoot { [CmdletBinding()] param(); return $script:HvgRoot }

function Test-HvgAdmin {
    [CmdletBinding()] param()
    try {
        $wp = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-HvgKnownHashesCsv {
    [CmdletBinding()] param()
    $p = Join-Path $script:HvgRoot 'findings\hashes.csv'
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

# =====================================================================================================
#  Persistence of the "posture snapshot" (baseline) across REBOOTS.
#  Needed because the crack's flow reboots the PC (VBS.cmd -> reboot -> F7 -> launch); an in-memory-only
#  snapshot would be lost. We save T1's JSON under %ProgramData%\HVGuard (or %LOCALAPPDATA% if there is
#  no permission), where the T2 watcher already lives. Read-only state; it does not touch protections.
# =====================================================================================================
function Get-HvgDataDir {
    [CmdletBinding()] param()
    foreach ($base in @($env:ProgramData, $env:LOCALAPPDATA, $env:TEMP)) {
        if (-not $base) { continue }
        $dir = Join-Path $base 'HVGuard'
        try {
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            $probe = Join-Path $dir ('.w' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
            Set-Content -LiteralPath $probe -Value 'x' -Encoding ascii -ErrorAction Stop
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            return $dir
        } catch { }
    }
    return (Join-Path $env:TEMP 'HVGuard')
}
function Get-HvgBaselineCandidate {
    $c = @()
    foreach ($base in @($env:ProgramData, $env:LOCALAPPDATA, $env:TEMP)) {
        if ($base) { $c += (Join-Path (Join-Path $base 'HVGuard') 'launch-baseline.json') }
    }
    return $c
}
function Get-HvgBaseline {
    [CmdletBinding()] param()
    foreach ($p in (Get-HvgBaselineCandidate)) {
        if (Test-Path -LiteralPath $p) {
            try {
                $raw = Get-Content -LiteralPath $p -Raw -Encoding UTF8
                if ($raw -and $raw.Trim()) { return ($raw | ConvertFrom-Json) }
            } catch { }
        }
    }
    return $null
}
function Clear-HvgBaseline {
    [CmdletBinding()] param()
    foreach ($p in (Get-HvgBaselineCandidate)) {
        try { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } } catch { }
    }
}
function Save-HvgBaseline {
    <# Saves the posture (T1's JSON) as a baseline. Source 'manual' (snapshot BEFORE M4) or 'auto'
       (Check turning green). An 'auto' does NOT overwrite a pending 'manual'. Returns $true/$false. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Posture, [string]$Source = 'manual', [string]$TargetPath = '')
    try {
        if ($Source -eq 'auto') {
            $existing = Get-HvgBaseline
            if ($existing -and "$($existing.source)" -eq 'manual') { return $true }
        }
        $rec = [ordered]@{
            timestampUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            timestampLocal = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            source         = $Source
            targetPath     = $TargetPath
            posture        = $Posture
        }
        Clear-HvgBaseline
        $p = Join-Path (Get-HvgDataDir) 'launch-baseline.json'
        ($rec | ConvertTo-Json -Depth 8) | Out-File -FilePath $p -Encoding utf8 -Force
        return $true
    } catch { return $false }
}

function Get-HvgDefenseScript {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $fileName = if ($script:HvgScriptMap.ContainsKey($Name)) { $script:HvgScriptMap[$Name] } else { $Name }
    if ($fileName -notmatch '\.ps1$') { $fileName = "$fileName.ps1" }
    foreach ($dir in $script:HvgDefenseDirs) {
        $cand = Join-Path $dir $fileName
        if (Test-Path -LiteralPath $cand) { return (Resolve-Path -LiteralPath $cand).Path }
    }
    return $null
}

function New-HvgTempPath {
    [CmdletBinding()]
    param([string]$Prefix = 'tool', [string]$Extension = 'json')
    $dir = Join-Path $env:TEMP 'HVGuard'
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force | Out-Null } catch { }
    }
    $stamp = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    return (Join-Path $dir ("{0}-{1}.{2}" -f $Prefix, $stamp, $Extension))
}

# =====================================================================================================
#  Command-line construction (CommandLineToArgvW-style quoting, valid on 5.1 and 7)
# =====================================================================================================
function ConvertTo-HvgArg {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    if ($s.Length -eq 0) { return '""' }
    if ($s -notmatch '[\s"]') { return $s }
    $s = [regex]::Replace($s, '(\\*)"', '$1$1\"')
    $s = [regex]::Replace($s, '(\\+)$', '$1$1')
    return '"' + $s + '"'
}

function ConvertTo-HvgParamTokens {
    param([hashtable]$Params)
    $tokens = @()
    if (-not $Params) { return $tokens }
    foreach ($k in $Params.Keys) {
        $v = $Params[$k]
        if ($v -is [bool] -or $v -is [switch]) {
            if ([bool]$v) { $tokens += "-$k" }
            continue
        }
        if ($null -eq $v) { continue }
        $tokens += "-$k"
        $tokens += [string]$v
    }
    return $tokens
}

# =====================================================================================================
#  Start-HvgTool: starts the child process and returns a "handle" (does NOT wait). Never throws.
# =====================================================================================================
function Start-HvgTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [hashtable]$Params,
        [string]$WorkingDirectory
    )
    $h = [ordered]@{
        Started = $false; Error = $null; Proc = $null; OutTask = $null; ErrTask = $null
        JsonPath = $null; ScriptPath = $null; Sw = $null; TimedOut = $false; ScriptName = $ScriptName
    }
    $scriptPath = Get-HvgDefenseScript -Name $ScriptName
    if (-not $scriptPath) {
        $h.Error = "Could not find the engine script '$ScriptName' in: $($script:HvgDefenseDirs -join '; ')"
        return [pscustomobject]$h
    }
    $h.ScriptPath = $scriptPath
    $jsonPath = New-HvgTempPath -Prefix $ScriptName -Extension 'json'
    $h.JsonPath = $jsonPath
    if (-not $WorkingDirectory) { $WorkingDirectory = $script:HvgRoot }

    $tokens = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath)
    $tokens += (ConvertTo-HvgParamTokens -Params $Params)
    $tokens += @('-AsJson', '-JsonPath', $jsonPath, '-Quiet')
    $argString = ($tokens | ForEach-Object { ConvertTo-HvgArg $_ }) -join ' '

    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName               = $script:HvgHostExe
        $psi.Arguments              = $argString
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow         = $true
        $psi.WindowStyle            = [System.Diagnostics.ProcessWindowStyle]::Hidden
        if (Test-Path -LiteralPath $WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo = $psi
        $h.Sw = [System.Diagnostics.Stopwatch]::StartNew()
        [void]$proc.Start()
        $h.Proc    = $proc
        $h.OutTask = $proc.StandardOutput.ReadToEndAsync()
        $h.ErrTask = $proc.StandardError.ReadToEndAsync()
        $h.Started = $true
    }
    catch {
        $h.Error = "Failed to launch '$ScriptName': $($_.Exception.Message)"
    }
    return [pscustomobject]$h
}

# =====================================================================================================
#  Complete-HvgTool: after the process exits (or is killed), builds the uniform result. Never throws.
# =====================================================================================================
function Complete-HvgTool {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Handle)

    $res = [ordered]@{
        Ok = $false; ExitCode = $null; Result = $null; Raw = ''; StdErr = ''
        TimedOut = [bool]$Handle.TimedOut; Error = $Handle.Error
        ScriptPath = $Handle.ScriptPath; JsonPath = $Handle.JsonPath; DurationMs = 0
    }
    if (-not $Handle.Started) { return [pscustomobject]$res }

    try { if ($Handle.Sw) { $Handle.Sw.Stop(); $res.DurationMs = $Handle.Sw.ElapsedMilliseconds } } catch { }
    try { $res.Raw    = $Handle.OutTask.Result } catch { }
    try { $res.StdErr = $Handle.ErrTask.Result } catch { }
    try { $res.ExitCode = $Handle.Proc.ExitCode } catch { $res.ExitCode = $null }
    try { $Handle.Proc.Dispose() } catch { }

    $obj = $null
    if ($Handle.JsonPath -and (Test-Path -LiteralPath $Handle.JsonPath)) {
        try {
            $rawJson = Get-Content -LiteralPath $Handle.JsonPath -Raw -Encoding UTF8 -ErrorAction Stop
            if ($rawJson -and $rawJson.Trim()) { $obj = $rawJson | ConvertFrom-Json -ErrorAction Stop }
        } catch { }
    }
    if ($null -eq $obj -and $res.Raw -and $res.Raw.Trim()) {
        try { $obj = $res.Raw | ConvertFrom-Json -ErrorAction Stop } catch { }
    }
    $res.Result = $obj
    $res.Ok = (-not $res.TimedOut) -and ($null -ne $res.ExitCode)

    try { if ($Handle.JsonPath -and (Test-Path -LiteralPath $Handle.JsonPath)) { Remove-Item -LiteralPath $Handle.JsonPath -Force -ErrorAction SilentlyContinue } } catch { }
    return [pscustomobject]$res
}

# =====================================================================================================
#  Invoke-HvgTool: SYNCHRONOUS version (starts + waits with timeout + completes). Never throws.
# =====================================================================================================
function Invoke-HvgTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [hashtable]$Params,
        [int]$TimeoutSec = 120,
        [string]$WorkingDirectory
    )
    $h = Start-HvgTool -ScriptName $ScriptName -Params $Params -WorkingDirectory $WorkingDirectory
    if (-not $h.Started) { return Complete-HvgTool -Handle $h }
    try {
        if (-not $h.Proc.WaitForExit($TimeoutSec * 1000)) {
            $h.TimedOut = $true
            try { $h.Proc.Kill() } catch { }
            try { [void]$h.Proc.WaitForExit(5000) } catch { }
        }
    } catch { $h.Error = $_.Exception.Message }
    return Complete-HvgTool -Handle $h
}

# =====================================================================================================
#  Import-HvgXaml: loads a XAML file (window or fragment) with XamlReader and returns it as an object.
#  Requires PresentationFramework to be loaded (HVGuard.ps1 does this). Runs under STA.
# =====================================================================================================
function Import-HvgXaml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "XAML not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $raw = [regex]::Replace($raw, '\s+x:Class="[^"]*"', '')
    $raw = [regex]::Replace($raw, '\s+mc:Ignorable="[^"]*"', '')
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($raw))
    try { return [System.Windows.Markup.XamlReader]::Load($reader) }
    finally { $reader.Dispose() }
}
