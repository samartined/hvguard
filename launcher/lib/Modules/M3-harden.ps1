# =====================================================================================================
#  HVGuard - Module M3: Harden (wraps T2 forced+monitor and T3 WDAC in AUDIT mode)
#  - "Harden": T2 -Enforce -InstallMonitor -> forces HVCI/VBS and leaves a watcher (events 7000/7001).
#  - "Audit drivers (WDAC)": T3 -Audit (AUDIT ONLY). The jump to real blocking (-Enforce) is NOT
#    exposed to a layperson's click (it can prevent boot): it is an advanced step documented in the runbook.
#  Respects $Ctx.ReadOnly: both actions require admin.
#  Contract: defines Initialize-HvgModule_M3Harden($Ctx).
# =====================================================================================================

$script:HvgM3 = @{ Panel = $null; Results = $null; BtnHarden = $null; BtnAudit = $null; S = $null }

function Get-HvgM3Strings {
    param([string]$Lang)
    $es = @{
        title      = 'Blindar y vigilar'
        intro      = 'Cierra el hueco que el bypass necesita y deja un vigilante. Nada de esto desactiva una proteccion: solo activa y observa.'
        hardenH    = '1) Blindar (activar tus protecciones mas profundas + vigilante)'
        hardenP    = 'Fuerza que tus protecciones mas profundas se queden activadas y deja una tarea que avisa si algo las apaga.'
        btnHarden  = 'Blindar ahora'
        auditH     = '2) Vigilar drivers sin firmar (solo observar)'
        auditP     = 'Activa un listado de drivers en modo solo-vigilancia: apunta que drivers sin firmar intentan cargarse, pero NO bloquea nada ni impide que tu equipo arranque.'
        btnAudit   = 'Vigilar drivers sin firmar (no bloquea)'
        hardening  = 'Blindando (T2: activar tus protecciones mas profundas + instalar vigilante)...'
        auditing   = 'Activando el listado de drivers, modo solo-vigilancia (T3)...'
        confHarden = 'Voy a activar tus protecciones mas profundas y dejar un vigilante que te avisa si algo las apaga. NO desactiva ninguna proteccion. Continuar?'
        confAudit  = 'Voy a activar un listado de drivers en modo solo-vigilancia. Solo observa y apunta lo que ve; NO bloquea drivers ni impide que tu equipo arranque. Continuar?'
        confTitle  = 'Confirmar'
        needAdmin  = 'Para blindar o auditar necesitas ejecutar HVGuard como administrador. Ahora estas en modo solo lectura.'
        watcher    = 'Vigilante instalado: la tarea "HVGuard-PostureMonitor" revisa la postura al inicio y cada hora. Si algo apaga HVCI/VBS, activa testsigning o aparece la clave ManageVBS, escribe un aviso en el Visor de eventos (Application, origen "HVGuard": 7000 = conforme, 7001 = deriva) y en %ProgramData%\HVGuard\posture-log.jsonl.'
        wdacNote   = 'Esto NO bloquea. Para pasar a bloqueo real (impedir cargar drivers sin firmar) hay que revisar antes los eventos de CodeIntegrity 3076/3077 y hacerlo con cuidado: puede impedir arrancar. Es un paso AVANZADO que HVGuard no ejecuta con un clic (ver el runbook).'
        reboot     = 'Puede hacer falta REINICIAR para que tus protecciones mas profundas surtan efecto. Luego vuelve a "Comprobar".'
        okHarden   = 'Blindaje aplicado.'
        okAudit    = 'Listado de drivers activado en modo solo-vigilancia.'
        errFmt     = 'Hubo un problema. Revisa los detalles.'
    }
    $en = @{
        title      = 'Harden and watch'
        intro      = 'Closes the gap the bypass needs and leaves a watcher. None of this disables a protection: it only enables and observes.'
        hardenH    = '1) Harden (turn on your deepest protections + a watcher)'
        hardenP    = 'Forces your deepest protections to stay on and leaves a task that alerts you if something turns them off.'
        btnHarden  = 'Harden now'
        auditH     = '2) Watch for unsigned drivers (observe only)'
        auditP     = 'Turns on a driver checklist in watch-only mode: it writes down which unsigned drivers try to load, but does NOT block anything or stop your PC from starting.'
        btnAudit   = 'Watch for unsigned drivers (does not block)'
        hardening  = 'Hardening (T2: turn on your deepest protections + install a watcher)...'
        auditing   = 'Turning on the driver checklist, watch-only mode (T3)...'
        confHarden = 'I will turn on your deepest protections and leave a watcher that alerts you if something turns them off. It does NOT disable any protection. Continue?'
        confAudit  = 'I will turn on a driver checklist in watch-only mode. It only observes and writes down what it sees; it does NOT block drivers or stop your PC from starting. Continue?'
        confTitle  = 'Confirm'
        needAdmin  = 'To harden or audit you must run HVGuard as administrator. You are in read-only mode now.'
        watcher    = 'Watcher installed: the "HVGuard-PostureMonitor" task checks posture at startup and hourly. If something turns off HVCI/VBS, enables testsigning or the ManageVBS key appears, it writes an alert to the Event Viewer (Application, source "HVGuard": 7000 = compliant, 7001 = drift) and to %ProgramData%\HVGuard\posture-log.jsonl.'
        wdacNote   = 'This does NOT block. Moving to real blocking (preventing unsigned drivers from loading) requires reviewing CodeIntegrity events 3076/3077 first and doing it carefully: it can prevent boot. It is an ADVANCED step HVGuard does not do with one click (see the runbook).'
        reboot     = 'A RESTART may be required for your deepest protections to take effect. Then go back to "Check".'
        okHarden   = 'Hardening applied.'
        okAudit    = 'Driver checklist turned on in watch-only mode.'
        errFmt     = 'There was a problem. See details.'
    }
    if ($Lang -eq 'en') { return $en } else { return $es }
}

function Show-HvgM3Result {
    param($Entries, [string]$Header, [bool]$Reboot, [string]$Extra)
    $s = $script:HvgM3.S
    $panel = $script:HvgM3.Results
    $panel.Children.Clear()
    [void]$panel.Children.Add((New-HvgParagraph -Text $Header))
    if ($Entries) {
        foreach ($e in @($Entries)) {
            $st = "$($e.status)"
            $lvl = switch ($st) { 'APPLIED' { 'ok' } 'OK' { 'ok' } 'WOULD' { 'warn' } 'PENDING' { 'warn' } 'WARN' { 'warn' } 'ERROR' { 'bad' } default { 'info' } }
            [void]$panel.Children.Add((New-HvgEvidenceCard -Level $lvl -Title ("{0}: {1}" -f $e.id, $e.name) -Detail "$($e.evidence)"))
        }
    }
    if ($Reboot) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.reboot -Detail '')) }
    if ($Extra) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level info -Title $Extra -Detail '')) }
}

function Enable-HvgM3Buttons {
    if ($script:HvgCtx.ReadOnly) { return }
    if ($script:HvgM3.BtnHarden) { $script:HvgM3.BtnHarden.IsEnabled = $true }
    if ($script:HvgM3.BtnAudit) { $script:HvgM3.BtnAudit.IsEnabled = $true }
}

function Invoke-HvgM3Harden {
    $s = $script:HvgM3.S
    if ($script:HvgCtx.ReadOnly) { [System.Windows.MessageBox]::Show($s.needAdmin, 'HVGuard', 'OK', 'Information') | Out-Null; return }
    if ([System.Windows.MessageBox]::Show($s.confHarden, $s.confTitle, 'YesNo', 'Warning') -ne 'Yes') { return }
    Set-HvgBusy -On $true -Text $s.hardening
    if ($script:HvgM3.BtnHarden) { $script:HvgM3.BtnHarden.IsEnabled = $false }
    if ($script:HvgM3.BtnAudit) { $script:HvgM3.BtnAudit.IsEnabled = $false }
    Invoke-HvgToolAsync -ScriptName T2 -Params @{ Enforce = $true; InstallMonitor = $true; Force = $true } -TimeoutSec 300 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM3.S.hardening, $sec) } `
        -OnDone {
        param($r)
        $s = $script:HvgM3.S
        try {
            $reboot = $false; try { $reboot = [bool]$r.Result.rebootRequired } catch { }
            $entries = $null; if ($r.Result) { $entries = $r.Result.actions }
            Show-HvgM3Result -Entries $entries -Header $s.okHarden -Reboot $reboot -Extra $s.watcher
            Set-HvgStatusBar -Text $s.okHarden
        }
        catch { Set-HvgStatusBar -Text ("M3: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; Enable-HvgM3Buttons }
    }
}

function Invoke-HvgM3Audit {
    $s = $script:HvgM3.S
    if ($script:HvgCtx.ReadOnly) { [System.Windows.MessageBox]::Show($s.needAdmin, 'HVGuard', 'OK', 'Information') | Out-Null; return }
    if ([System.Windows.MessageBox]::Show($s.confAudit, $s.confTitle, 'YesNo', 'Warning') -ne 'Yes') { return }
    Set-HvgBusy -On $true -Text $s.auditing
    if ($script:HvgM3.BtnHarden) { $script:HvgM3.BtnHarden.IsEnabled = $false }
    if ($script:HvgM3.BtnAudit) { $script:HvgM3.BtnAudit.IsEnabled = $false }
    # AUDIT ONLY. Never -Enforce from the GUI (risk of failing to boot).
    Invoke-HvgToolAsync -ScriptName T3 -Params @{ Audit = $true; Force = $true } -TimeoutSec 300 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM3.S.auditing, $sec) } `
        -OnDone {
        param($r)
        $s = $script:HvgM3.S
        try {
            $entries = $null; if ($r.Result) { $entries = $r.Result.log }
            Show-HvgM3Result -Entries $entries -Header $s.okAudit -Reboot $false -Extra $s.wdacNote
            Set-HvgStatusBar -Text $s.okAudit
        }
        catch { Set-HvgStatusBar -Text ("M3: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; Enable-HvgM3Buttons }
    }
}

function Initialize-HvgModule_M3Harden {
    param($Ctx)
    $panel = $Ctx.Window.FindName('PanelHarden')
    $panel.Children.Clear()
    $s = Get-HvgM3Strings -Lang $Ctx.Lang
    $script:HvgM3.S = $s
    $script:HvgM3.Panel = $panel

    $root = [System.Windows.Controls.StackPanel]::new()
    $root.Margin = [System.Windows.Thickness]::new(4)
    [void]$root.Children.Add((New-HvgHeading -Text $s.title))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.intro))

    if ($Ctx.ReadOnly) { [void]$root.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.needAdmin -Detail '')) }

    # Section 1: Harden
    [void]$root.Children.Add((New-HvgHeading -Text $s.hardenH))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.hardenP -FontSize 12 -Color '#6B7280'))
    $btnH = [System.Windows.Controls.Button]::new()
    $btnH.Content = $s.btnHarden; $btnH.MinWidth = 160; $btnH.MinHeight = 40
    $btnH.FontWeight = [System.Windows.FontWeights]::SemiBold
    $btnH.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $btnH.Margin = [System.Windows.Thickness]::new(0, 2, 0, 14)
    $btnH.IsEnabled = (-not $Ctx.ReadOnly)
    $btnH.Add_Click({ Invoke-HvgM3Harden })
    [void]$root.Children.Add($btnH)
    $script:HvgM3.BtnHarden = $btnH

    # Section 2: Audit WDAC
    [void]$root.Children.Add((New-HvgHeading -Text $s.auditH))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.auditP -FontSize 12 -Color '#6B7280'))
    $btnA = [System.Windows.Controls.Button]::new()
    $btnA.Content = $s.btnAudit; $btnA.MinWidth = 180; $btnA.MinHeight = 40
    $btnA.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $btnA.Margin = [System.Windows.Thickness]::new(0, 2, 0, 12)
    $btnA.IsEnabled = (-not $Ctx.ReadOnly)
    $btnA.Add_Click({ Invoke-HvgM3Audit })
    [void]$root.Children.Add($btnA)
    $script:HvgM3.BtnAudit = $btnA

    [void]$root.Children.Add((New-HvgCopyAllButton -Label $Ctx.T.CopyAll -CopiedText $Ctx.T.Copied -GetContainer { $script:HvgM3.Results }))
    # The scroll comes from the tab's ScrollViewer (Shell.xaml); here it's just a StackPanel that grows.
    $results = [System.Windows.Controls.StackPanel]::new()
    [void]$root.Children.Add($results)
    $script:HvgM3.Results = $results

    [void]$panel.Children.Add($root)
}
