#Requires -Version 5.1
<#
.SYNOPSIS
    HVGuard - launcher/GUI (PowerShell + WPF) that wraps the validated defensive suite (defense\T0..T5, T7)
    for a NON-technical user. Auto-elevates to Administrator; if UAC is cancelled, degrades to READ-ONLY.

.DESCRIPTION
    Entry point. Bootstrap responsibilities:
      1) Guarantee the STA apartment (WPF requires it; PowerShell 7 starts in MTA -> relaunch in STA).
      2) Auto-elevate (Start-Process -Verb RunAs). If the user cancels UAC -> read-only mode.
      3) Load the engine (lib\Engine.ps1), the UI helpers (lib\UI.ps1), i18n (lib\i18n\*.psd1) and the
         window (lib\Shell.xaml via XamlReader).
      4) Build $Ctx, discover and start the modules (lib\Modules\M*.ps1), wire up the language
         selector and show the window.

    Does NOT execute, install or launch anything from the sample. Does NOT disable protections. Any
    action that changes the system is performed by the engine (T2/T3/T5) in the direction of hardening,
    and only from modules that expose it with confirmation. In "Watch while you play" it is the USER who
    launches the game; HVGuard only observes.

.PARAMETER ReadOnly     Forces read-only mode (does not attempt to elevate).
.PARAMETER Relaunched   (internal) marks that the process has already relaunched; avoids relaunch loops.
.PARAMETER Lang         Forces the language ('es'|'en'). Default: system culture (es->es, else->en).
.PARAMETER SelfTest     Builds and shows the window OFF-SCREEN and closes it itself after -SelfTestMs;
                        prints a summary and exits. For automated render validation (does not elevate).
.PARAMETER SelfTestMs   Milliseconds the window stays open in -SelfTest (default 1500).

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7. Version: 1.0.1
#>
[CmdletBinding()]
param(
    [switch]$ReadOnly,
    [switch]$Relaunched,
    [ValidateSet('', 'es', 'en')][string]$Lang = '',
    [switch]$SelfTest,
    [int]$SelfTestMs = 1500,
    [string]$Shot = '',
    [string]$ShotTab = '',
    [int]$ShotHeight = 0
)

$ErrorActionPreference = 'Stop'

$LauncherDir = $PSScriptRoot
$LibDir      = Join-Path $LauncherDir 'lib'

function Test-HvgBootstrapAdmin {
    try {
        $wp = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# =====================================================================================================
#  (1)+(2) Relaunch for STA and/or elevation
# =====================================================================================================
$needSTA = ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA')
$isAdmin = Test-HvgBootstrapAdmin
$forcedReadOnly = $false

if (-not $Relaunched) {
    # We do not attempt to elevate if we are already admin, if the user requested -ReadOnly, or if this is a self-test.
    $wantElevate = (-not $isAdmin) -and (-not $ReadOnly) -and (-not $SelfTest)
    if ($needSTA -or $wantElevate) {
        try { $hostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
        catch { $hostExe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' } }

        $pt = @()
        if ($Lang)     { $pt += @('-Lang', $Lang) }
        if ($SelfTest) { $pt += '-SelfTest'; $pt += @('-SelfTestMs', "$SelfTestMs") }
        if ($Shot)     { $pt += @('-Shot', ('"' + $Shot + '"')) }
        $qFile = '"' + $PSCommandPath + '"'
        $argStr = ("-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File $qFile -Relaunched " + ($pt -join ' ')).Trim()

        try {
            if ($wantElevate) { Start-Process -FilePath $hostExe -ArgumentList $argStr -Verb RunAs | Out-Null }
            else              { Start-Process -FilePath $hostExe -ArgumentList $argStr           | Out-Null }
            exit 0
        } catch {
            if ($wantElevate) {
                # UAC cancelled (or other elevation failure) -> continue in READ-ONLY mode.
                $roStr = ("-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File $qFile -Relaunched -ReadOnly " + ($pt -join ' ')).Trim()
                if ($needSTA) {
                    try { Start-Process -FilePath $hostExe -ArgumentList $roStr | Out-Null; exit 0 } catch { }
                }
                $forcedReadOnly = $true   # already STA here: continue inline in read-only mode
            } else {
                Write-Error "Could not start HVGuard in STA mode: $($_.Exception.Message)"
                exit 2
            }
        }
    }
}

$effectiveReadOnly = [bool]$ReadOnly -or (-not $isAdmin) -or $forcedReadOnly

# =====================================================================================================
#  (3) Load assemblies, engine, UI, i18n and window
# =====================================================================================================
try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
} catch {
    Write-Error "Could not load the WPF assemblies: $($_.Exception.Message)"
    exit 2
}

. (Join-Path $LibDir 'Engine.ps1')
. (Join-Path $LibDir 'UI.ps1')

# Hide the host console during normal use (nicety; never during self-test, to preserve logs).
if (-not $SelfTest) {
    try {
        if (-not ('HvgNativeWin' -as [type])) {
            Add-Type -Namespace HvgNative -Name Win -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@ -ErrorAction Stop
        }
        $h = [HvgNative.Win]::GetConsoleWindow()
        if ($h -ne [IntPtr]::Zero) { [void][HvgNative.Win]::ShowWindow($h, 0) }  # 0 = SW_HIDE
    } catch { }
}

# --- i18n: explicit UTF-8 read (preserves accents on 5.1 and 7) ---------------------------------------
function Import-HvgStrings {
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $sb = [scriptblock]::Create($raw)
    return (& $sb)
}
function Resolve-HvgLang {
    param([string]$Pref)
    if ($Pref -eq 'es' -or $Pref -eq 'en') { return $Pref }
    try { if ([System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'es') { return 'es' } } catch { }
    return 'en'
}

$allChrome = @{}
try {
    $allChrome['es'] = Import-HvgStrings (Join-Path $LibDir 'i18n\es.psd1')
    $allChrome['en'] = Import-HvgStrings (Join-Path $LibDir 'i18n\en.psd1')
} catch {
    # Minimal fallback so the window opens even if a psd1 fails.
    $fb = @{ AppTitle='HVGuard'; AppSubtitle=''; LangLabel='Lang'; Ready='Ready'; DetailsHeader='Details';
             Tabs=@{Status='Check';Repair='Repair';Harden='Harden';Folder='Folder';Scanner='Scanner'};
             Status=@{NotChecked='NOT CHECKED';Working='CHECKING';Protected='PROTECTED';AtRisk='AT RISK';Compromised='COMPROMISED';Unknown='INCONCLUSIVE'};
             StatusHintDefault=''; ReadOnlyBanner='Read-only'; ReadOnlyTag='read-only'; AdminTag='admin'; NeverFalseSecurity=''; CopyAll='Copy all'; Copied='Copied.' }
    if (-not $allChrome.ContainsKey('es')) { $allChrome['es'] = $fb }
    if (-not $allChrome.ContainsKey('en')) { $allChrome['en'] = $fb }
}
$lang = Resolve-HvgLang -Pref $Lang

# --- Window -------------------------------------------------------------------------------------------
$window = Import-HvgXaml -Path (Join-Path $LibDir 'Shell.xaml')

# =====================================================================================================
#  (4) Context, chrome, modules, language
# =====================================================================================================
$Ctx = [pscustomobject]@{
    Window   = $window
    ReadOnly = $effectiveReadOnly
    Elevated = $isAdmin
    Root     = (Get-HvgRoot)
    LibDir   = $LibDir
    Lang     = $lang
    Chrome   = $allChrome
    T        = $allChrome[$lang]
    SelfTest = [bool]$SelfTest
}

# Script-scope variables for use from event handlers (reliable resolution).
$script:HvgCtx     = $Ctx
$script:HvgWindow  = $window
Initialize-HvgUI -Ctx $Ctx

function Set-HvgChrome {
    $t = $script:HvgCtx.T
    $w = $script:HvgWindow
    try {
        $w.Title = $t.AppTitle
        $w.FindName('AppTitle').Text    = $t.AppTitle
        $w.FindName('AppSubtitle').Text = $t.AppSubtitle
        $w.FindName('LangLabel').Text   = $t.LangLabel
        $w.FindName('DetailsExpander').Header = $t.DetailsHeader
        $w.FindName('TabStatus').Header  = $t.Tabs.Status
        $w.FindName('TabRepair').Header  = $t.Tabs.Repair
        $w.FindName('TabHarden').Header  = $t.Tabs.Harden
        $w.FindName('TabFolder').Header  = $t.Tabs.Folder
        $w.FindName('TabScanner').Header = $t.Tabs.Scanner
    } catch { }
}

function Invoke-HvgModuleInit {
    # (Re)initializes all modules in the current language. Each module clears its Grid and rebuilds itself.
    $script:HvgInitErrors = @()
    foreach ($fn in $script:HvgModuleInits) {
        try { & $fn.Name $script:HvgCtx }
        catch {
            $script:HvgInitErrors += ("{0}: {1}" -f $fn.Name, $_.Exception.Message)
            Set-HvgStatusBar -Text ("Module {0}: {1}" -f $fn.Name, $_.Exception.Message)
        }
    }
}

function Switch-HvgLanguage {
    param([string]$NewLang)
    if ($NewLang -ne 'es' -and $NewLang -ne 'en') { return }
    if ($NewLang -eq $script:HvgCtx.Lang) { return }
    $script:HvgCtx.Lang = $NewLang
    $script:HvgCtx.T    = $script:HvgCtx.Chrome[$NewLang]
    Set-HvgChrome
    Invoke-HvgModuleInit
    # Re-apply the status light/base state consistent with the language.
    Set-HvgStatus -State 'NotChecked' -Hint $script:HvgCtx.T.StatusHintDefault
    if ($script:HvgCtx.ReadOnly) { Set-HvgStatusBar -Text $script:HvgCtx.T.ReadOnlyBanner }
    else { Set-HvgStatusBar -Text $script:HvgCtx.T.Ready }
}

# Chrome + initial state
Set-HvgChrome
Set-HvgStatus -State 'NotChecked' -Hint $Ctx.T.StatusHintDefault
if ($effectiveReadOnly) { Set-HvgStatusBar -Text $Ctx.T.ReadOnlyBanner }
else { Set-HvgStatusBar -Text $Ctx.T.Ready }

# --- Discover and start modules -----------------------------------------------------------------------
$modDir = Join-Path $LibDir 'Modules'
if (Test-Path -LiteralPath $modDir) {
    foreach ($mf in (Get-ChildItem -LiteralPath $modDir -Filter 'M*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try { . $mf.FullName } catch { Set-HvgStatusBar -Text ("Could not load {0}: {1}" -f $mf.Name, $_.Exception.Message) }
    }
}
$script:HvgModuleInits = @(Get-Command -CommandType Function -Name 'Initialize-HvgModule_*' -ErrorAction SilentlyContinue | Sort-Object Name)
Invoke-HvgModuleInit

# --- Language selector --------------------------------------------------------------------------------
$script:HvgLangSel = $window.FindName('LangSelector')
foreach ($it in $script:HvgLangSel.Items) { if ([string]$it.Tag -eq $lang) { $script:HvgLangSel.SelectedItem = $it; break } }
$script:HvgLangSel.Add_SelectionChanged({
        try {
            $sel = $script:HvgLangSel.SelectedItem
            if ($sel) { Switch-HvgLanguage -NewLang ([string]$sel.Tag) }
        } catch { }
    })

# From here on, event handlers must not bring down the dispatcher due to non-terminating errors.
$ErrorActionPreference = 'Continue'

# =====================================================================================================
#  Show the window (or auto-close it in self-test)
# =====================================================================================================
if ($SelfTest) {
    $window.WindowStartupLocation = 'Manual'
    $window.Left = -32000; $window.Top = -32000
    $window.ShowActivated = $false
    if ($ShotTab) { try { $t = $window.FindName("Tab$ShotTab"); if ($t) { $window.FindName('MainTabs').SelectedItem = $t } } catch { } }
    if ($ShotHeight -gt 0) { $window.Height = $ShotHeight }
    $script:HvgRendered = $false
    $script:HvgShot = $Shot
    $window.Add_ContentRendered({
            $script:HvgRendered = $true
            if ($script:HvgShot) {
                try {
                    $w = [int]$script:HvgWindow.ActualWidth; $hh = [int]$script:HvgWindow.ActualHeight
                    if ($w -gt 0 -and $hh -gt 0) {
                        $rtb = [System.Windows.Media.Imaging.RenderTargetBitmap]::new($w, $hh, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
                        $rtb.Render($script:HvgWindow)
                        $enc = [System.Windows.Media.Imaging.PngBitmapEncoder]::new()
                        [void]$enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
                        $fs = [System.IO.File]::Create($script:HvgShot)
                        try { $enc.Save($fs) } finally { $fs.Close() }
                    }
                } catch { }
            }
        })
    $script:HvgSelfTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $script:HvgSelfTimer.Interval = [TimeSpan]::FromMilliseconds([Math]::Max(300, $SelfTestMs))
    $script:HvgSelfTimer.Add_Tick({ $script:HvgSelfTimer.Stop(); try { $script:HvgWindow.Close() } catch { } })
    $script:HvgSelfTimer.Start()
    try { [void]$window.ShowDialog() } catch { Write-Output "SELFTEST error: $($_.Exception.Message)"; exit 2 }
    Write-Output ("SELFTEST rendered={0} readonly={1} elevated={2} lang={3} modules={4} initErrors={5}" -f `
            $script:HvgRendered, $Ctx.ReadOnly, $Ctx.Elevated, $Ctx.Lang, $script:HvgModuleInits.Count, @($script:HvgInitErrors).Count)
    foreach ($e in @($script:HvgInitErrors)) { Write-Output ("  INIT-ERR {0}" -f $e) }
    exit ($(if ($script:HvgRendered -and @($script:HvgInitErrors).Count -eq 0) { 0 } else { 2 }))
}
else {
    try { [void]$window.ShowDialog() }
    catch {
        try { [System.Windows.MessageBox]::Show("HVGuard could not start:`n$($_.Exception.Message)", 'HVGuard', 'OK', 'Error') | Out-Null } catch { }
        exit 2
    }
}
exit 0
