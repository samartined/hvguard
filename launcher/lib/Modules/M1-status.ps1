# =====================================================================================================
#  HVGuard - Module M1: Check (wraps T1 posture + T0 detector)  [READ-ONLY]
#  Runs T1 and T0 and combines them into the global PROTECTED/AT RISK/COMPROMISED status light, with the
#  evidence cards in the "View details" expander. Always available (also in read-only mode).
#  Contract: defines Initialize-HvgModule_M1Status($Ctx). Uses helpers from UI.ps1 and the engine via Invoke-HvgTool.
# =====================================================================================================

$script:HvgM1 = @{ Panel = $null; Result = $null; Btn = $null; S = $null }

function Get-HvgM1Strings {
    param([string]$Lang)
    $es = @{
        title    = 'Comprobar el estado de tu equipo'
        intro    = 'Reviso tu equipo sin cambiar nada: si tus protecciones mas profundas estan activas, si Windows todavia comprueba que los drivers estan bien firmados, y si hay rastros conocidos de que se uso el crack. Es una lectura, no una garantia.'
        btn      = 'Comprobar ahora'
        checking = 'Comprobando el estado del equipo (T1 + T0)...'
        done     = 'Comprobacion terminada.'
        failRun  = 'No se pudo completar la comprobacion. Revisa los detalles.'
        lastNone = 'Aun no has comprobado. Pulsa "Comprobar ahora".'
        lastFmt  = 'Ultima comprobacion: {0}'
        seeAbove = 'El resultado y el porque estan arriba, en el semaforo y en "Ver detalles".'
        never    = 'Recuerda: el verde significa "no encontre amenazas conocidas", nunca "es seguro".'
        evFmt    = "actual: {0}  |  esperado: {1}`n{2}"
        hProtected   = 'No encontre amenazas conocidas y tus protecciones clave estan activas. Esto reduce el riesgo, pero no es una garantia de seguridad.'
        hAtRisk      = 'Alguna proteccion esta debil o hay senales a revisar, aunque no detecte el crack activo. Ve a "Reparar" y "Blindar".'
        hCompromised = 'Detecte senales del bypass o de que se preparo/uso en este equipo. Ve a "Reparar" cuanto antes.'
        hUnknown     = 'No pude evaluarlo todo (por ejemplo, sin permisos de administrador). Reinicia como administrador para una lectura completa.'
    }
    $en = @{
        title    = 'Check your PC state'
        intro    = 'Reads your PC without changing anything: whether your deepest protections are switched on, whether Windows still checks that drivers are properly signed, and whether there are known traces that the crack was used. This is a reading, not a guarantee.'
        btn      = 'Check now'
        checking = 'Checking the PC state (T1 + T0)...'
        done     = 'Check finished.'
        failRun  = 'The check could not be completed. See details.'
        lastNone = 'Not checked yet. Click "Check now".'
        lastFmt  = 'Last check: {0}'
        seeAbove = 'The result and the why are above, in the status light and "View details".'
        never    = 'Remember: green means "no known threats found", never "it is safe".'
        evFmt    = "current: {0}  |  expected: {1}`n{2}"
        hProtected   = 'No known threats found and your key protections are active. This lowers the risk, but is not a guarantee of safety.'
        hAtRisk      = 'Some protection is weak or there are signals to review, though I did not detect the crack running. See "Repair" and "Harden".'
        hCompromised = 'I detected signs of the bypass or that it was prepared/used on this PC. Go to "Repair" as soon as possible.'
        hUnknown     = 'I could not evaluate everything (for example, without administrator rights). Restart as administrator for a full reading.'
    }
    if ($Lang -eq 'en') { return $en } else { return $es }
}

function Get-HvgM1Verdict {
    <# Combines the T1 and T0 JSON into @{ State; Hint; Cards[] }. Testable without GUI (under STA + WPF). #>
    param($T1, $T0, $S)
    $cards = @()
    $t1o = if ($T1) { "$($T1.overall)" } else { '' }
    $t0o = if ($T0) { "$($T0.overall)" } else { '' }
    # Localized "current / expected" line. Falls back to English so the function stays usable
    # standalone (e.g. from a test harness) where the string table has not been initialized.
    $evFmt = if ($S -and $S.evFmt) { $S.evFmt } else { "current: {0}  |  expected: {1}`n{2}" }

    if ($T1 -and $T1.checks) {
        foreach ($c in $T1.checks) {
            $st = "$($c.status)"
            $isCore = $false; try { $isCore = [bool]$c.core } catch { }
            if (-not ($isCore -or $st -eq 'FAIL' -or "$($c.id)" -like 'IOC*')) { continue }
            $lvl = switch ($st) { 'PASS' { 'ok' } 'FAIL' { 'bad' } 'WARN' { 'warn' } 'UNKNOWN' { 'warn' } default { 'info' } }
            $cards += New-HvgEvidenceCard -Level $lvl -Title ("{0}  ({1})" -f $c.name, $c.id) `
                -Detail ($evFmt -f $c.observed, $c.expected, $c.evidence)
        }
    }
    if ($T0 -and $T0.findings) {
        foreach ($fi in $T0.findings) {
            if ("$($fi.status)" -ne 'ALERT') { continue }
            $cards += New-HvgEvidenceCard -Level 'bad' -Title ("{0}  ({1}/{2})" -f $fi.name, $fi.id, $fi.severity) `
                -Detail ($evFmt -f $fi.observed, $fi.expected, $fi.evidence)
        }
    }

    if ($t0o -eq 'DETECTED') { $state = 'Compromised'; $hint = $S.hCompromised }
    elseif ($t1o -eq 'FAIL' -or $t0o -eq 'SUSPECTED') { $state = 'AtRisk'; $hint = $S.hAtRisk }
    elseif (-not $T1 -or -not $T0 -or $t1o -eq 'INCONCLUSIVE') { $state = 'Unknown'; $hint = $S.hUnknown }
    elseif ($t1o -eq 'PASS' -and $t0o -eq 'CLEAN') { $state = 'Protected'; $hint = $S.hProtected }
    else { $state = 'Unknown'; $hint = $S.hUnknown }

    return @{ State = $state; Hint = $hint; Cards = @($cards) }
}

function Invoke-HvgM1Check {
    # Asynchronous: T1 -> (on completion) T0 -> verdict. Does NOT block the window; shows seconds.
    $s = $script:HvgM1.S
    Set-HvgStatus -State 'Working' -Hint $s.checking
    Set-HvgBusy -On $true -Text $s.checking
    if ($script:HvgM1.Btn) { $script:HvgM1.Btn.IsEnabled = $false }
    Invoke-HvgToolAsync -ScriptName T1 -TimeoutSec 120 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM1.S.checking, $sec) } `
        -OnDone {
        param($t1)
        $script:HvgM1._t1 = $t1
        Invoke-HvgToolAsync -ScriptName T0 -TimeoutSec 180 `
            -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM1.S.checking, $sec) } `
            -OnDone {
            param($t0)
            $s = $script:HvgM1.S
            try {
                $v = Get-HvgM1Verdict -T1 $script:HvgM1._t1.Result -T0 $t0.Result -S $s
                Set-HvgStatus -State $v.State -Hint $v.Hint
                Set-HvgDetails -Cards $v.Cards
                # Automatic baseline: if the posture is green, save it as a "known-good state" (does
                # not overwrite a manual BEFORE snapshot) to allow comparison after playing, even after a restart.
                if ($v.State -eq 'Protected') { [void](Save-HvgBaseline -Posture $script:HvgM1._t1.Result -Source 'auto') }
                $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                if ($script:HvgM1.Result) { $script:HvgM1.Result.Text = ($s.lastFmt -f $stamp) + "  -  " + $s.seeAbove }
                Set-HvgStatusBar -Text $s.done
            }
            catch {
                Set-HvgStatus -State 'Unknown' -Hint $s.failRun
                Set-HvgStatusBar -Text ("M1: " + $_.Exception.Message)
            }
            finally {
                Set-HvgBusy -On $false -Text ''
                if ($script:HvgM1.Btn) { $script:HvgM1.Btn.IsEnabled = $true }
            }
        }
    }
}

function Initialize-HvgModule_M1Status {
    param($Ctx)
    $panel = $Ctx.Window.FindName('PanelStatus')
    $panel.Children.Clear()
    $s = Get-HvgM1Strings -Lang $Ctx.Lang
    $script:HvgM1.S = $s
    $script:HvgM1.Panel = $panel

    $stack = [System.Windows.Controls.StackPanel]::new()
    $stack.Margin = [System.Windows.Thickness]::new(4)

    [void]$stack.Children.Add((New-HvgHeading -Text $s.title))
    [void]$stack.Children.Add((New-HvgParagraph -Text $s.intro))

    $btn = [System.Windows.Controls.Button]::new()
    $btn.Content = $s.btn
    $btn.MinWidth = 170; $btn.MinHeight = 42
    $btn.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $btn.FontWeight = [System.Windows.FontWeights]::SemiBold
    $btn.Margin = [System.Windows.Thickness]::new(0, 4, 0, 10)
    $btn.Add_Click({ Invoke-HvgM1Check })
    [void]$stack.Children.Add($btn)
    $script:HvgM1.Btn = $btn

    $rt = [System.Windows.Controls.TextBlock]::new()
    $rt.Text = $s.lastNone
    $rt.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $rt.Foreground = New-HvgBrush '#374151'
    $rt.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)
    [void]$stack.Children.Add($rt)
    $script:HvgM1.Result = $rt

    # Copies all the evidence from the status light (the global "View details" ItemsControl).
    [void]$stack.Children.Add((New-HvgCopyAllButton -Label $Ctx.T.CopyAll -CopiedText $Ctx.T.Copied -GetContainer { $script:HvgCtx.Window.FindName('DetailsContent') }))

    $note = New-HvgParagraph -Text $s.never -Color '#6B7280' -FontSize 12
    [void]$stack.Children.Add($note)

    [void]$panel.Children.Add($stack)
}
