#Requires -Version 5.1
<#
.SYNOPSIS
    T7 - Known-threat scanner over a TARGET file or folder (e.g. the already-installed game folder,
    or an installer). READ-ONLY: does not execute, load, or modify ANYTHING.

.DESCRIPTION
    Engine behind HVGuard modules M4 (game folder) and M5 (scanner). Reuses the logic of
    tools\pe-triage.py but 100% in native PowerShell (no dependency on Python on the user's machine).
    For each file (recursively, if the target is a folder):
      - SHA-256 (Get-FileHash) against findings\hashes.csv (distinguishes rows flagged as IOC from
        known-benign rows from the package).
      - Authenticode signature (Get-AuthenticodeSignature): status + publisher.
      - Native PE heuristics: architecture, suspicious imports (network/injection/persistence/driver,
        from the pe-triage.py taxonomy), per-section entropy (packer), and whether it is an unsigned .sys.
      - Name/structure IOC: exact names of DenuvOwO components (SimpleSvm.sys, hyperkd.sys,
        hyperhv.dll, hyperevade.dll, hypervisor-launcher.exe, VBS.cmd, DenuvOwO.nfo, DenuoOwO_SRC.7z...),
        the 'elamigos' marker, and stray .sys/.cmd files next to the game.
      - Optional YARA: if yara64.exe/yara.exe is present, runs defense\telemetry\yara\denuvowo.yar.
      - OPT-IN hash reputation (-OnlineHashLookup): queries VirusTotal with ONLY the hash (never
        uploads the file). API key via environment variable (HVGUARD_VT_API_KEY or VT_API_KEY). Off by default.

    Classification by CONFIDENCE, without mixing levels:
      KNOWN-THREAT   -> hash flagged as IOC, exact name of a crack component, hypervisor YARA match, or
                        malicious online reputation. High confidence.
      SUSPECT-SIGNALS-> PE heuristics (dropper imports, high entropy, unsigned .sys), weak markers
                        (elamigos), name-based YARA. Lower confidence: "review".
      CLEAN          -> no known signals (NOT a guarantee that it is safe).

    Philosophy (HVGuard): NEVER give a false sense of security. "Clean" = "found no known threats".

.PARAMETER Target            File or folder to analyze (required).
.PARAMETER OnlineHashLookup  Opt-in: query hash reputation (VirusTotal). Hash only, never the file.
.PARAMETER KnownHashesCsv    CSV with a 'sha256' column (+ optional 'is_relevant'/'ioc_reason'). Def: findings\hashes.csv.
.PARAMETER MaxHashBytes      Maximum size to compute hash/entropy/YARA per file (def. 256 MB). Avoids
                             hashing giant blobs (e.g. elamigos-*.bin files of tens of GB).
.PARAMETER MaxFiles          Cap on files to inspect (def. 20000). If exceeded, a warning is shown (not silent).
.PARAMETER YaraPath          Path to yara64.exe/yara.exe. Def: auto-detect in PATH / HVGUARD_YARA.
.PARAMETER AsJson / -JsonPath / -Quiet   Same as T0-T5.

.OUTPUTS
    Exit: 0 = CLEAN | 1 = KNOWN-THREAT | 2 = SUSPECT-SIGNALS or ERROR.

.NOTES
    Blue team project. Does NOT touch the sample: analyzes it statically. Consistent with the taxonomy of
    tools\pe-triage.py (4 ultra-generic network tokens -send/recv/connect/socket- are omitted to reduce
    false positives; the rest of the set is identical). Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [switch]$OnlineHashLookup,
    [string]$KnownHashesCsv,
    [long]$MaxHashBytes = 268435456,
    [int]$MaxFiles = 20000,
    [string]$YaraPath,
    [switch]$AsJson,
    [string]$JsonPath,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Platform -----------------------------------------------------------------------------------------
$onWindows = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }
if (-not $onWindows) { Write-Error 'T7 only applies to Windows (uses Get-AuthenticodeSignature / Windows PE).'; exit 2 }

$IsElevated = $false
try { $IsElevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }

$ScriptDir = $PSScriptRoot
$RepoRoot  = Split-Path -Parent $ScriptDir
$EntropyCapBytes = 16MB   # do not read huge sections for entropy (packed code is small)

# --- Suspicious import taxonomy (ported from pe-triage.py; without the 4 ultra-generic tokens) --------
$SuspectApi = [ordered]@{
    red          = @('InternetOpen', 'InternetConnect', 'HttpSendRequest', 'URLDownloadToFile', 'WinHttpOpen', 'WinHttpConnect', 'WSAStartup', 'gethostbyname', 'InternetReadFile', 'URLDownloadToCacheFile')
    inyeccion    = @('WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx', 'NtMapViewOfSection', 'QueueUserApc', 'SetWindowsHookEx', 'NtUnmapViewOfSection', 'RtlCreateUserThread', 'NtWriteVirtualMemory')
    proceso      = @('CreateProcess', 'ShellExecute', 'WinExec', 'NtCreateUserProcess')
    persistencia = @('RegSetValueEx', 'RegCreateKeyEx', 'CreateServiceA', 'CreateServiceW', 'OpenSCManager')
    driver       = @('ZwLoadDriver', 'NtLoadDriver', 'ZwSetSystemInformation')
    'cripto/anti' = @('CryptEncrypt', 'CryptDecrypt', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess')
}

# --- Name IOC: exact crack components (high confidence) and weak markers -------------------------------
$StrongNames = @(
    'simplesvm.sys', 'hyperkd.sys', 'hyperhv.dll', 'hyperevade.dll', 'hypervisor-launcher.exe',
    'vbs.cmd', 'denuvowo.nfo', 'denuoowo_src.7z', 'efiguarddxe.efi', 'loader.efi'
)
# Name substrings that are a strong signal even if the extension/case changes.
$StrongNameParts = @('denuvowo', 'denuoowo', 'hyperevade', 'hyperkd', 'simplesvm')

# =====================================================================================================
#  Utilities
# =====================================================================================================
$Items = [System.Collections.Generic.List[object]]::new()

function New-Item2 {
    param($Path, $Name, [long]$Size, [string]$Class, $Signals)
    return [pscustomobject]@{
        path = $Path; name = $Name; sizeBytes = $Size; classification = $Class
        signals = @($Signals)
    }
}

function Get-ShannonEntropy {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return 0.0 }
    $counts = [int[]]::new(256)
    foreach ($b in $Bytes) { $counts[$b]++ }
    $len = [double]$Bytes.Length
    $ent = 0.0
    foreach ($c in $counts) { if ($c -gt 0) { $p = $c / $len; $ent -= $p * [Math]::Log($p, 2) } }
    return [Math]::Round($ent, 3)
}

function Read-Bytes {
    param([System.IO.FileStream]$Fs, [long]$Offset, [int]$Count)
    if ($Offset -lt 0 -or $Offset -ge $Fs.Length -or $Count -le 0) { return $null }
    $toRead = [int][Math]::Min([long]$Count, $Fs.Length - $Offset)
    if ($toRead -le 0) { return $null }
    [void]$Fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $buf = [byte[]]::new($toRead)
    $n = $Fs.Read($buf, 0, $toRead)
    if ($n -le 0) { return $null }
    if ($n -lt $toRead) { $tmp = [byte[]]::new($n); [Array]::Copy($buf, $tmp, $n); return $tmp }
    return $buf
}

# --- Native PE parser (best-effort; never throws to the caller) ----------------------------------------
function Get-PeInfo {
    param([string]$Path, [long]$Size)
    $info = [ordered]@{ isPE = $false; arch = ''; isDll = $false; subsystem = ''; timestamp = ''
        imports = @(); maxEntropy = 0.0; sections = @(); securityDirSize = 0; parseNote = '' }
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($fs.Length -lt 64) { return $info }
        $hdrLen = [int][Math]::Min([long]65536, $fs.Length)
        $hdr = Read-Bytes -Fs $fs -Offset 0 -Count $hdrLen
        if (-not $hdr -or $hdr.Length -lt 64) { return $info }
        if ($hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) { return $info }   # 'MZ'
        $elfanew = [BitConverter]::ToInt32($hdr, 0x3C)
        if ($elfanew -le 0 -or ($elfanew + 24) -ge $hdr.Length) { $info.parseNote = 'e_lfanew out of header bounds'; return $info }
        if (-not ($hdr[$elfanew] -eq 0x50 -and $hdr[$elfanew + 1] -eq 0x45 -and $hdr[$elfanew + 2] -eq 0 -and $hdr[$elfanew + 3] -eq 0)) { $info.parseNote = 'no PE signature'; return $info }
        $info.isPE = $true

        $coff = $elfanew + 4
        $machine = [BitConverter]::ToUInt16($hdr, $coff)
        $numSec = [BitConverter]::ToUInt16($hdr, $coff + 2)
        $tsRaw = [BitConverter]::ToUInt32($hdr, $coff + 8)
        $sizeOpt = [BitConverter]::ToUInt16($hdr, $coff + 16)
        $chars = [BitConverter]::ToUInt16($hdr, $coff + 18)
        $info.isDll = (($chars -band 0x2000) -ne 0)
        switch ($machine) {
            0x14c { $info.arch = 'x86' }
            0x8664 { $info.arch = 'x64' }
            0xAA64 { $info.arch = 'arm64' }
            0x1c0 { $info.arch = 'arm' }
            default { $info.arch = ('0x{0:x}' -f $machine) }
        }
        try { $info.timestamp = [DateTimeOffset]::FromUnixTimeSeconds([long]$tsRaw).UtcDateTime.ToString('yyyy-MM-dd') } catch { $info.timestamp = "$tsRaw" }

        $opt = $coff + 20
        if (($opt + 2) -ge $hdr.Length) { $info.parseNote = 'optional header out of header bounds'; return $info }
        $magic = [BitConverter]::ToUInt16($hdr, $opt)
        $isPE32Plus = ($magic -eq 0x20B)
        $ddOffset = if ($isPE32Plus) { $opt + 112 } else { $opt + 96 }
        if (($opt + 70) -lt $hdr.Length) { $info.subsystem = [BitConverter]::ToUInt16($hdr, $opt + 68) }

        # Data directories: idx1 = import, idx4 = security (Authenticode)
        $impRva = 0; $impSize = 0
        if (($ddOffset + 16) -lt $hdr.Length) {
            $impRva = [BitConverter]::ToUInt32($hdr, $ddOffset + 8)
            $impSize = [BitConverter]::ToUInt32($hdr, $ddOffset + 12)
        }
        if (($ddOffset + 40) -lt $hdr.Length) {
            $info.securityDirSize = [BitConverter]::ToUInt32($hdr, $ddOffset + 4 * 8 + 4)
        }

        # Section headers
        $secStart = $opt + $sizeOpt
        $sections = @()
        for ($i = 0; $i -lt $numSec; $i++) {
            $so = $secStart + ($i * 40)
            if (($so + 40) -gt $hdr.Length) { break }
            $nameBytes = [byte[]]($hdr[$so..($so + 7)])
            $name = ([System.Text.Encoding]::ASCII.GetString($nameBytes)).TrimEnd([char]0)
            $vsize = [BitConverter]::ToUInt32($hdr, $so + 8)
            $vaddr = [BitConverter]::ToUInt32($hdr, $so + 12)
            $rawSize = [BitConverter]::ToUInt32($hdr, $so + 16)
            $rawPtr = [BitConverter]::ToUInt32($hdr, $so + 20)
            $sections += [pscustomobject]@{ Name = $name; VirtualSize = $vsize; VirtualAddress = $vaddr; SizeOfRawData = $rawSize; PointerToRawData = $rawPtr }
        }

        # Per-section entropy (capped)
        $secOut = @(); $maxEnt = 0.0
        foreach ($s in $sections) {
            $ent = 0.0
            if ($s.SizeOfRawData -gt 0 -and $s.PointerToRawData -gt 0 -and $s.SizeOfRawData -le $EntropyCapBytes) {
                $sb = Read-Bytes -Fs $fs -Offset $s.PointerToRawData -Count ([int][Math]::Min([long]$s.SizeOfRawData, [long]$EntropyCapBytes))
                if ($sb) { $ent = Get-ShannonEntropy -Bytes $sb }
            }
            if ($ent -gt $maxEnt) { $maxEnt = $ent }
            $secOut += [pscustomobject]@{ name = $s.Name; entropy = $ent; size = [long]$s.SizeOfRawData }
        }
        $info.sections = $secOut
        $info.maxEntropy = $maxEnt

        # Imports (best-effort)
        if ($impRva -gt 0) {
            $imports = [System.Collections.Generic.List[string]]::new()
            $thunkSize = if ($isPE32Plus) { 8 } else { 4 }
            $ordinalFlag = if ($isPE32Plus) { ([uint64]1 -shl 63) } else { [uint64]0x80000000 }
            $impOff = Rva2Off $impRva $sections
            $guard = 0
            while ($impOff -ge 0 -and $guard -lt 4096) {
                $guard++
                $desc = Read-Bytes -Fs $fs -Offset $impOff -Count 20
                if (-not $desc -or $desc.Length -lt 20) { break }
                $oft = [BitConverter]::ToUInt32($desc, 0)
                $nameRva = [BitConverter]::ToUInt32($desc, 12)
                $ft = [BitConverter]::ToUInt32($desc, 16)
                if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
                $thunkRva = if ($oft -ne 0) { $oft } else { $ft }
                $thunkOff = Rva2Off $thunkRva $sections
                $tguard = 0
                while ($thunkOff -ge 0 -and $tguard -lt 8192 -and $imports.Count -lt 5000) {
                    $tguard++
                    $tb = Read-Bytes -Fs $fs -Offset $thunkOff -Count $thunkSize
                    if (-not $tb -or $tb.Length -lt $thunkSize) { break }
                    $val = if ($isPE32Plus) { [BitConverter]::ToUInt64($tb, 0) } else { [uint64][BitConverter]::ToUInt32($tb, 0) }
                    if ($val -eq 0) { break }
                    if (($val -band $ordinalFlag) -eq 0) {
                        $nameOff = Rva2Off ([uint32]($val -band 0x7FFFFFFF)) $sections
                        if ($nameOff -ge 0) {
                            $nb = Read-Bytes -Fs $fs -Offset ($nameOff + 2) -Count 128
                            if ($nb) {
                                $zero = [Array]::IndexOf($nb, [byte]0)
                                $len = if ($zero -ge 0) { $zero } else { $nb.Length }
                                if ($len -gt 0) { $imports.Add([System.Text.Encoding]::ASCII.GetString($nb, 0, $len)) }
                            }
                        }
                    }
                    $thunkOff += $thunkSize
                }
                $impOff += 20
            }
            $info.imports = @($imports | Sort-Object -Unique)
        }
    }
    catch { $info.parseNote = $_.Exception.Message }
    finally { if ($fs) { try { $fs.Dispose() } catch { } } }
    return $info
}

function Rva2Off {
    param([uint32]$Rva, $Sections)
    foreach ($s in $Sections) {
        $span = [Math]::Max([long]$s.VirtualSize, [long]$s.SizeOfRawData)
        if ($span -le 0) { $span = $s.SizeOfRawData }
        if ($Rva -ge $s.VirtualAddress -and $Rva -lt ($s.VirtualAddress + $span)) {
            return [long]$s.PointerToRawData + ($Rva - $s.VirtualAddress)
        }
    }
    return -1
}

# =====================================================================================================
#  Loading known hashes (IOC vs benign)
# =====================================================================================================
$knownThreat = @{}   # sha256(lower) -> reason
$knownBenign = @{}   # sha256(lower) -> description
if (-not $KnownHashesCsv) { $KnownHashesCsv = Join-Path $RepoRoot 'findings\hashes.csv' }
if ($KnownHashesCsv -and (Test-Path -LiteralPath $KnownHashesCsv)) {
    try {
        foreach ($r in (Import-Csv -LiteralPath $KnownHashesCsv)) {
            $props = $r.PSObject.Properties.Name
            if ($props -notcontains 'sha256' -or -not $r.sha256) { continue }
            $sha = ([string]$r.sha256).ToLower().Trim()
            if (-not $sha) { continue }
            $isRel = ($props -contains 'is_relevant' -and "$($r.is_relevant)".Trim() -eq '1')
            $reason = if ($props -contains 'ioc_reason') { "$($r.ioc_reason)".Trim() } else { '' }
            $desc = if ($props -contains 'file_desc' -and $r.file_desc) { "$($r.file_desc)" } elseif ($props -contains 'relative_path') { "$($r.relative_path)" } else { '' }
            if ($isRel -or $reason) { $knownThreat[$sha] = $(if ($reason) { $reason } else { 'flagged as IOC in hashes.csv' }) }
            else { $knownBenign[$sha] = $desc }
        }
    } catch { }
}

# =====================================================================================================
#  YARA (optional)
# =====================================================================================================
$yaraExe = $null
$yaraRules = Join-Path $ScriptDir 'telemetry\yara\denuvowo.yar'
if (-not $YaraPath) { if ($env:HVGUARD_YARA) { $YaraPath = $env:HVGUARD_YARA } }
foreach ($cand in @($YaraPath, 'yara64.exe', 'yara.exe', 'yara64', 'yara')) {
    if (-not $cand) { continue }
    try {
        if ((Test-Path -LiteralPath $cand -ErrorAction SilentlyContinue)) { $yaraExe = (Resolve-Path -LiteralPath $cand).Path; break }
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { $yaraExe = $cmd.Source; break }
    } catch { }
}
$yaraAvailable = ($yaraExe -and (Test-Path -LiteralPath $yaraRules))

function Invoke-YaraScan {
    param([string]$File)
    # Returns @{ names=@(...) }: names of matching rules. Best-effort.
    $out = @{ names = @() }
    if (-not $yaraAvailable) { return $out }
    try {
        $raw = & $yaraExe $yaraRules $File 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) {
            $names = @()
            foreach ($line in @($raw)) {
                $tok = ([string]$line).Trim()
                if (-not $tok) { continue }
                # format: "RULENAME <path>"
                $rule = ($tok -split '\s+', 2)[0]
                if ($rule) { $names += $rule }
            }
            $out.names = @($names | Sort-Object -Unique)
        }
    } catch { }
    return $out
}

# =====================================================================================================
#  Online reputation by HASH (opt-in). NEVER uploads the file.
# =====================================================================================================
$vtApiKey = $null
if ($OnlineHashLookup) {
    foreach ($n in @('HVGUARD_VT_API_KEY', 'VT_API_KEY')) {
        if (-not $vtApiKey) {
            $val = [System.Environment]::GetEnvironmentVariable($n)
            if ($val) { $vtApiKey = $val }
        }
    }
}
function Invoke-HashReputation {
    param([string]$Sha256)
    # -> @{ available=$bool; malicious=$int; note=$string }
    $r = @{ available = $false; malicious = 0; note = '' }
    if (-not $OnlineHashLookup) { return $r }
    if (-not $vtApiKey) { $r.note = 'no API key (set HVGUARD_VT_API_KEY)'; return $r }
    if (-not $Sha256) { $r.note = 'no hash'; return $r }
    try {
        $resp = Invoke-RestMethod -Method Get -Uri ("https://www.virustotal.com/api/v3/files/{0}" -f $Sha256) `
            -Headers @{ 'x-apikey' = $vtApiKey } -TimeoutSec 15 -ErrorAction Stop
        $r.available = $true
        $stats = $resp.data.attributes.last_analysis_stats
        if ($stats) { $r.malicious = [int]$stats.malicious }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match '404') { $r.note = 'hash not known to VT (404)' } else { $r.note = "VT query failed: $msg" }
    }
    return $r
}

# =====================================================================================================
#  Target enumeration
# =====================================================================================================
if (-not (Test-Path -LiteralPath $Target)) {
    $err = "Target not found: $Target"
    $result = [ordered]@{ tool = 'T7-target-scan'; version = '1.0.0'; timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); hostname = $env:COMPUTERNAME; elevated = $IsElevated; target = $Target; overall = 'ERROR'; exitCode = 2; error = $err; counts = @{ scanned = 0; known = 0; suspect = 0; clean = 0 }; items = @() }
    $json = $result | ConvertTo-Json -Depth 6
    if ($JsonPath) { try { $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force } catch { } }
    if ($AsJson) { Write-Output $json } elseif (-not $Quiet) { Write-Host $err -ForegroundColor Red }
    exit 2
}

$targetItem = Get-Item -LiteralPath $Target
$isDir = $targetItem.PSIsContainer
$files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$truncated = $false
if ($isDir) {
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $Target -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($files.Count -ge $MaxFiles) { $truncated = $true; break }
            $files.Add($f)
        }
    } catch { }
} else {
    $files.Add([System.IO.FileInfo]$targetItem.FullName)
}

$scriptExts = @('.cmd', '.bat', '.ps1', '.vbs', '.js', '.nfo', '.txt', '.inf', '.7z')

# =====================================================================================================
#  Per-file analysis
# =====================================================================================================
foreach ($f in $files) {
    $signals = [System.Collections.Generic.List[object]]::new()
    $class = 'CLEAN'
    $nameLower = $f.Name.ToLower()
    $ext = $f.Extension.ToLower()

    function Add-Signal { param($Type, $Sev, $Detail) $signals.Add([pscustomobject]@{ type = $Type; severity = $Sev; detail = $Detail }) }
    function Escalate { param($To) if ($To -eq 'KNOWN-THREAT') { $script:__c = 'KNOWN-THREAT' } elseif ($To -eq 'SUSPECT-SIGNALS' -and $script:__c -ne 'KNOWN-THREAT') { $script:__c = 'SUSPECT-SIGNALS' } }
    $script:__c = 'CLEAN'

    # --- (1) Name / structure IOC (always, cheap) ---
    if ($StrongNames -contains $nameLower) {
        Add-Signal 'ioc-name' 'critical' ("Exact name of a DenuvOwO crack component: {0}" -f $f.Name)
        Escalate 'KNOWN-THREAT'
    } else {
        foreach ($p in $StrongNameParts) { if ($nameLower -like "*$p*") { Add-Signal 'ioc-name' 'high' ("File name contains a crack-component marker: '{0}'" -f $p); Escalate 'KNOWN-THREAT'; break } }
    }
    if ($nameLower -like '*elamigos*') { Add-Signal 'ioc-marker' 'medium' "Marker 'elamigos' in the name (ElAmigos repack: context, not proof of malware)."; Escalate 'SUSPECT-SIGNALS' }

    # --- MZ detection + depth decision ---
    $isPE = $false
    $canOpen = $true
    try {
        $fs0 = [System.IO.File]::Open($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { $two = [byte[]]::new(2); [void]$fs0.Read($two, 0, 2); $isPE = ($two.Length -eq 2 -and $two[0] -eq 0x4D -and $two[1] -eq 0x5A) } finally { $fs0.Dispose() }
    } catch { $canOpen = $false; Add-Signal 'access' 'low' ("Could not open for analysis: {0}" -f $_.Exception.Message) }

    $isScriptish = ($scriptExts -contains $ext)
    $withinSize = ($f.Length -le $MaxHashBytes)
    $deepEligible = $canOpen -and ($isPE -or $isScriptish -or $withinSize)

    # --- Stray .sys / .cmd files in the target (structure signal) ---
    if ($ext -eq '.sys') { Add-Signal 'ioc-struct' 'medium' 'Driver (.sys) present in the target. Unsigned drivers from a game/crack are suspicious.'; Escalate 'SUSPECT-SIGNALS' }
    if ($ext -eq '.cmd' -or $ext -eq '.bat') { Add-Signal 'ioc-struct' 'low' 'Script .cmd/.bat present (the crack VBS.cmd toggles protections; review its contents).' }

    # --- (2) Hash + reputation (only if openable and within size limit) ---
    $sha = $null
    if ($canOpen -and $withinSize) {
        try { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName -ErrorAction Stop).Hash.ToLower() } catch { Add-Signal 'hash' 'low' ("Could not hash: {0}" -f $_.Exception.Message) }
    } elseif (-not $withinSize) {
        Add-Signal 'size' 'low' ("Large file ({0:N0} MB > limit): hash/entropy/YARA skipped. Name/structure analysis only." -f ($f.Length / 1MB))
    }
    if ($sha) {
        if ($knownThreat.ContainsKey($sha)) { Add-Signal 'hash-ioc' 'critical' ("SHA-256 matches a known IOC: {0}" -f $knownThreat[$sha]); Escalate 'KNOWN-THREAT' }
        elseif ($knownBenign.ContainsKey($sha)) { Add-Signal 'hash-known' 'info' ("SHA-256 matches a known file from the package (not flagged as a threat): {0}" -f $knownBenign[$sha]) }
    }

    # --- (3) Signature + PE heuristics ---
    $sigStatus = ''; $signer = ''
    if ($isPE -and $canOpen) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
            $sigStatus = "$($sig.Status)"
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        } catch { $sigStatus = 'n/a' }
        $signed = ($sigStatus -eq 'Valid')

        $pe = Get-PeInfo -Path $f.FullName -Size $f.Length
        $hitCats = @()
        if ($pe.imports -and $pe.imports.Count -gt 0) {
            foreach ($cat in $SuspectApi.Keys) {
                $apis = $SuspectApi[$cat]
                $found = @()
                foreach ($imp in $pe.imports) { foreach ($a in $apis) { if ($imp.ToLower().Contains($a.ToLower())) { $found += $imp; break } } }
                $found = @($found | Sort-Object -Unique)
                if ($found.Count -gt 0) { $hitCats += $cat; Add-Signal 'pe-import' $(if ($cat -in @('inyeccion', 'driver')) { 'high' } elseif ($cat -eq 'red') { 'medium' } else { 'low' }) ("Imports for '{0}': {1}" -f $cat, (($found | Select-Object -First 6) -join ', ')) }
            }
        }
        # Signature
        if (-not $signed) {
            $sev = if ($ext -eq '.sys') { 'high' } else { 'medium' }
            Add-Signal 'signature' $sev ("PE without a valid signature (status: {0}). A repacked crack component is usually unsigned." -f $(if ($sigStatus) { $sigStatus } else { 'unknown' }))
        } else {
            Add-Signal 'signature' 'info' ("Signed and valid: {0}" -f $signer)
        }
        # Entropy (packer) - only relevant if NOT signed (signed binaries legitimately compress resources)
        if ($pe.maxEntropy -ge 7.2 -and -not $signed) {
            Add-Signal 'entropy' 'medium' ("High section entropy ({0}): possible packing/encryption." -f $pe.maxEntropy)
        }

        # Decide SUSPECT via heuristics: unsigned PE with dropper imports, or unsigned .sys, or high entropy without a signature.
        $dropper = @($hitCats | Where-Object { $_ -eq 'inyeccion' -or $_ -eq 'driver' -or $_ -eq 'red' }).Count -gt 0
        if (-not $signed -and ($dropper -or $ext -eq '.sys' -or $pe.maxEntropy -ge 7.2)) { Escalate 'SUSPECT-SIGNALS' }
        elseif ($dropper -and -not $signed) { Escalate 'SUSPECT-SIGNALS' }

        # Record useful PE metadata
        Add-Signal 'pe-info' 'info' ("PE {0} {1}{2} max_entropy={3}{4}" -f $pe.arch, $(if ($pe.isDll) { 'DLL' } else { 'EXE' }), $(if ($pe.timestamp) { " ts=$($pe.timestamp)" } else { '' }), $pe.maxEntropy, $(if ($pe.parseNote) { " (note: $($pe.parseNote))" } else { '' }))
    }

    # --- (4) YARA (if available and eligible) ---
    if ($yaraAvailable -and $deepEligible) {
        $y = Invoke-YaraScan -File $f.FullName
        foreach ($rule in $y.names) {
            if ($rule -match 'SimpleSvm|HyperDbg') { Add-Signal 'yara' 'critical' ("Hypervisor YARA rule: {0}" -f $rule); Escalate 'KNOWN-THREAT' }
            else { Add-Signal 'yara' 'medium' ("YARA rule (weak name-based signal): {0}" -f $rule); Escalate 'SUSPECT-SIGNALS' }
        }
    }

    # --- (5) Online hash reputation (opt-in) ---
    if ($OnlineHashLookup -and $sha) {
        $rep = Invoke-HashReputation -Sha256 $sha
        if ($rep.available) {
            if ($rep.malicious -gt 0) { Add-Signal 'reputation' 'critical' ("VirusTotal: {0} engines flag this hash as malicious." -f $rep.malicious); Escalate 'KNOWN-THREAT' }
            else { Add-Signal 'reputation' 'info' 'VirusTotal: 0 detections for this hash (not a guarantee).' }
        } elseif ($rep.note) { Add-Signal 'reputation' 'low' ("Online reputation: {0}" -f $rep.note) }
    }

    $class = $script:__c
    $Items.Add((New-Item2 -Path $f.FullName -Name $f.Name -Size $f.Length -Class $class -Signals $signals))
}

# =====================================================================================================
#  Verdict
# =====================================================================================================
$known = @($Items | Where-Object { $_.classification -eq 'KNOWN-THREAT' })
$suspect = @($Items | Where-Object { $_.classification -eq 'SUSPECT-SIGNALS' })
$clean = @($Items | Where-Object { $_.classification -eq 'CLEAN' })

if ($known.Count -gt 0) { $overall = 'KNOWN-THREAT'; $exit = 1 }
elseif ($suspect.Count -gt 0) { $overall = 'SUSPECT-SIGNALS'; $exit = 2 }
else { $overall = 'CLEAN'; $exit = 0 }

$result = [ordered]@{
    tool = 'T7-target-scan'; version = '1.0.0'
    timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname = $env:COMPUTERNAME; elevated = $IsElevated
    target = (Resolve-Path -LiteralPath $Target).Path
    targetType = $(if ($isDir) { 'folder' } else { 'file' })
    overall = $overall; exitCode = $exit
    counts = [ordered]@{ scanned = $Items.Count; known = $known.Count; suspect = $suspect.Count; clean = $clean.Count; truncated = $truncated }
    scan = [ordered]@{ yara = [bool]$yaraAvailable; online = [bool]$OnlineHashLookup; maxHashBytes = $MaxHashBytes; knownHashesCsv = $(if (Test-Path -LiteralPath $KnownHashesCsv) { (Resolve-Path -LiteralPath $KnownHashesCsv).Path } else { '' }) }
    # Only files with signals (avoids noise from thousands of clean items in a large folder).
    items = @($Items | Where-Object { $_.classification -ne 'CLEAN' -or (@($_.signals).Count -gt 0) } | Select-Object -First 500)
}

$json = $result | ConvertTo-Json -Depth 8
if ($JsonPath) { try { $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force } catch { Write-Warning "JSON: $($_.Exception.Message)" } }

if ($AsJson) { Write-Output $json }
elseif (-not $Quiet) {
    $col = @{ 'KNOWN-THREAT' = 'Red'; 'SUSPECT-SIGNALS' = 'Yellow'; 'CLEAN' = 'Green' }
    Write-Host ''
    Write-Host '================ T7 - Known-threat scanner (read-only) ================' -ForegroundColor Cyan
    Write-Host ("Target: {0}" -f $result.target)
    Write-Host ("Files: {0}   KNOWN-THREAT: {1}   SUSPECT: {2}   CLEAN: {3}{4}" -f $Items.Count, $known.Count, $suspect.Count, $clean.Count, $(if ($truncated) { "   (TRUNCATED to $MaxFiles)" } else { '' }))
    Write-Host ("YARA: {0}   Online reputation: {1}" -f [bool]$yaraAvailable, [bool]$OnlineHashLookup) -ForegroundColor DarkGray
    Write-Host '-----------------------------------------------------------------------------------'
    foreach ($it in ($Items | Where-Object { $_.classification -ne 'CLEAN' })) {
        Write-Host ("[{0}] {1}" -f $it.classification, $it.path) -ForegroundColor $col[$it.classification]
        foreach ($s in $it.signals) { if ($s.severity -ne 'info') { Write-Host ("      - ({0}) {1}" -f $s.severity, $s.detail) -ForegroundColor DarkGray } }
    }
    Write-Host '-----------------------------------------------------------------------------------'
    $ovc = $col[$overall]
    Write-Host ("VERDICT: {0} (exit {1})" -f $overall, $exit) -ForegroundColor $ovc
    Write-Host 'Remember: "clean" = "found no known threats", NEVER "is safe".' -ForegroundColor DarkGray
    Write-Host '===================================================================================' -ForegroundColor Cyan
    Write-Host ''
}
exit $exit
