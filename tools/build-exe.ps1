#Requires -Version 5.1
<#
.SYNOPSIS
    Builds HVGuard.exe: a single self-contained .exe that embeds all the scripts and launches the GUI.
    Offline and with nothing to install: uses the .NET Framework csc.exe (preinstalled on Win10/11).

.DESCRIPTION
    1) Packages launcher/ + defense/*.ps1 + defense/telemetry/ + findings/hashes.csv into a ZIP.
    2) Injects a build-id into the C# stub (tools/exe/HVGuardLauncher.cs).
    3) Compiles with csc /target:winexe embedding the ZIP as a resource, with a manifest (asInvoker) and icon.
    Result: dist/HVGuard.exe. The engine and GUI are NOT reimplemented; the .exe only carries and launches them.

.NOTES
    The .exe is not signed. To distribute, apply an Authenticode signature:  signtool sign /fd SHA256 /a dist\HVGuard.exe
#>
[CmdletBinding()]
param([switch]$KeepTemp)

$ErrorActionPreference = 'Stop'
$repo    = Split-Path -Parent $PSScriptRoot
$exeDir  = Join-Path $PSScriptRoot 'exe'
$dist    = Join-Path $repo 'dist'
$srcCs   = Join-Path $exeDir 'HVGuardLauncher.cs'
$manifest= Join-Path $exeDir 'app.manifest'
$ico     = Join-Path $exeDir 'hvguard.ico'
$outExe  = Join-Path $dist 'HVGuard.exe'

if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Force $dist | Out-Null }

# --- locate csc.exe (.NET Framework) ---
$csc = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) { throw 'csc.exe from .NET Framework 4.x was not found.' }
$fw = Split-Path $csc
Write-Host "csc: $csc" -ForegroundColor DarkGray

# --- resolve reference assemblies not included in csc.rsp by default ---
function Find-Ref([string]$name) {
    $cands = @(
        (Join-Path $fw $name),
        "${env:ProgramFiles(x86)}\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8\$name",
        "${env:ProgramFiles(x86)}\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\$name"
    )
    foreach ($c in $cands) { if ($c -and (Test-Path $c)) { return $c } }
    return $name   # last resort: let csc resolve it
}
$refComp   = Find-Ref 'System.IO.Compression.dll'
$refCompFs = Find-Ref 'System.IO.Compression.FileSystem.dll'

# --- payload staging ---
$stage = Join-Path $env:TEMP ("hvg-stage-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
$zip   = Join-Path $env:TEMP ("hvg-payload-" + [Guid]::NewGuid().ToString('N').Substring(0,8) + ".zip")
New-Item -ItemType Directory -Force $stage | Out-Null
try {
    # launcher/ (without binaries)
    Copy-Item (Join-Path $repo 'launcher') (Join-Path $stage 'launcher') -Recurse -Force
    Get-ChildItem (Join-Path $stage 'launcher') -Recurse -Include *.exe, *.dll -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    # defense: T*.ps1 scripts + telemetry (for YARA/sigma/sysmon)
    New-Item -ItemType Directory -Force (Join-Path $stage 'defense') | Out-Null
    Copy-Item (Join-Path $repo 'defense\*.ps1') (Join-Path $stage 'defense') -Force
    if (Test-Path (Join-Path $repo 'defense\telemetry')) {
        Copy-Item (Join-Path $repo 'defense\telemetry') (Join-Path $stage 'defense\telemetry') -Recurse -Force
    }
    # findings: only hashes.csv (what T7 uses by default)
    New-Item -ItemType Directory -Force (Join-Path $stage 'findings') | Out-Null
    Copy-Item (Join-Path $repo 'findings\hashes.csv') (Join-Path $stage 'findings\hashes.csv') -Force

    $files = (Get-ChildItem $stage -Recurse -File).Count
    Write-Host "payload: $files files" -ForegroundColor DarkGray

    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    Write-Host ("zip: {0:N0} bytes" -f (Get-Item $zip).Length) -ForegroundColor DarkGray

    # --- inject build-id into the stub ---
    $buildId = 'b' + (Get-Date -Format 'yyyyMMddHHmmss')
    $genCs = Join-Path $env:TEMP ("HVGuardLauncher-$buildId.cs")
    (Get-Content -LiteralPath $srcCs -Raw -Encoding UTF8).Replace('__BUILDID__', $buildId) | Set-Content -LiteralPath $genCs -Encoding UTF8
    Write-Host "buildId: $buildId" -ForegroundColor DarkGray

    # --- compile ---
    if (Test-Path $outExe) { Remove-Item $outExe -Force }
    $args = @(
        '/nologo', '/target:winexe', '/platform:anycpu', '/optimize+',
        "/out:$outExe",
        "/win32manifest:$manifest",
        "/win32icon:$ico",
        "/reference:$refComp",
        "/reference:$refCompFs",
        "/resource:$zip,HVGuard.payload.zip",
        $genCs
    )
    Write-Host 'compiling...' -ForegroundColor Cyan
    & $csc @args
    $code = $LASTEXITCODE
    if ($code -ne 0 -or -not (Test-Path $outExe)) { throw "csc failed (exit $code)." }

    $fi = Get-Item $outExe
    Write-Host ("OK -> {0}  ({1:N0} bytes)" -f $fi.FullName, $fi.Length) -ForegroundColor Green
    Write-Host ("Version: {0}  Product: {1}" -f $fi.VersionInfo.FileVersion, $fi.VersionInfo.ProductName) -ForegroundColor DarkGray
    if (-not $KeepTemp) { Remove-Item $genCs -Force -ErrorAction SilentlyContinue }
}
finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $KeepTemp) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
}
