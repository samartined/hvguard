# =====================================================================================================
#  HVGuard - Module M4: Game folder (scan + posture correlation + launch delta)
#  Idea A reframed (plan 06 section 6.4): the path is a scan target + watchpoint, NOT a
#  process to follow.
#    - "Analyze this folder": T7 (scanner) + T1 (posture) -> correlates.
#    - "Watch while playing": posture snapshot (T1) BEFORE; the USER launches the game ON THEIR OWN;
#      "I closed the game" button; snapshot AFTER; reports whether the launch degraded the defenses.
#    - Optional watch: alert if new .sys/.cmd files appear (DispatcherTimer, without touching the process).
#
#  HARD GUARDRAIL (CLAUDE.md section 1): HVGuard NEVER launches, runs or opens the game or anything
#  from the sample. Here it ONLY takes posture readings and scans the folder. The user launches the
#  game themselves.
#  Contract: defines Initialize-HvgModule_M4Folder($Ctx).
# =====================================================================================================

$script:HvgM4 = @{ Panel = $null; PathBox = $null; Results = $null; S = $null
    Before = $null; Watch = $null; WatchBaseline = $null
    BtnAnalyze = $null; BtnBefore = $null; BtnAfter = $null; ChkWatch = $null
}

function Get-HvgM4Strings {
    param([string]$Lang)
    $es = @{
        title    = 'Carpeta del juego'
        intro    = 'La carpeta del juego es donde viven los componentes del crack. Aqui puedo (1) escanearla en busca de componentes conocidos y cruzarlo con tus protecciones, y (2) vigilar que le hace el lanzamiento a tus defensas. Importante: mientras el crack esta realmente en marcha, su parte mas profunda es invisible para mi; mi ventaja es antes de que cargue, y las huellas que deja despues.'
        pathLbl  = 'Ruta de la carpeta del juego (o un .exe):'
        browse   = 'Elegir...'
        btnAnalyze = 'Analizar esta carpeta'
        analyzeH = 'Analisis de la carpeta'
        analyzing = 'Analizando la carpeta (T7) y comprobando tus protecciones (T1)...'
        noPath   = 'Primero elige una carpeta valida.'
        watchH   = 'Vigilar al jugar (foto antes / juegas tu / foto despues)'
        watchP   = 'HVGuard NUNCA lanza el juego: lo lanzas TU. Yo solo tomo una foto de tus protecciones antes y otra despues para ver si el lanzamiento las apago.'
        btnBefore = 'Tomar foto ANTES de jugar'
        btnAfter  = 'Ya cerre el juego -> foto DESPUES'
        beforeOk  = 'Foto ANTES tomada y GUARDADA (se conserva aunque reinicies el equipo). AHORA lanza el juego TU (HVGuard no lo hace); si el crack pide reiniciar, hazlo. Al terminar, abre HVGuard y pulsa "Ya cerre el juego".'
        pendingFmt = 'Tienes una foto ANTES guardada del {0}{1}. Cuando cierres el juego, pulsa "Ya cerre el juego" para comparar.'
        afterRun  = 'Tomando foto DESPUES y comparando...'
        chkWatch  = 'Avisar si aparecen .sys/.cmd nuevos en la carpeta mientras vigilo'
        deltaBadH = 'El lanzamiento DEGRADO tus defensas:'
        deltaOkH  = 'No detecte que el lanzamiento degradara tus defensas.'
        deltaLimit = 'Limite honesto: lo que el crack cargue en la parte mas profunda de tu equipo es invisible para mi MIENTRAS esta corriendo. Que no vea una caida no garantiza que no pasara nada; solo que tus protecciones clave seguian activas en la foto de despues.'
        iocAppeared = 'Aparecio una marca de seguimiento que deja el crack: senal de que la tecnica se preparo o se uso.'
        corrCompromised = 'Estado COMPROMETIDO: esta carpeta trae componentes del crack Y tus protecciones estan debiles. El bypass puede establecerse.'
        corrComponents  = 'Hay componentes del crack en la carpeta, pero tus protecciones clave (HVCI) siguen activas: no puede cargarse mientras las mantengas. Considera Reparar/Blindar y borrar esos componentes.'
        corrPostureBad  = 'No encontre componentes conocidos en la carpeta, pero tus protecciones estan debiles. Ve a "Reparar" y "Blindar".'
        corrClean       = 'No encontre componentes conocidos del crack en la carpeta y tus protecciones clave estan activas. (No es una garantia de seguridad.)'
        newFileFmt = 'Aparecio un fichero nuevo en la carpeta: {0}'
        never    = 'Recuerda: "limpio" = "no encontre amenazas conocidas", nunca "es seguro".'
        beforeNeeded = 'Toma primero la foto ANTES.'
        watchOn  = 'Vigilancia de carpeta ACTIVA.'
        watchOff = 'Vigilancia de carpeta detenida.'
        regFmt       = 'antes: PASS  ->  despues: FAIL. {0}'
        countsFmt    = 'Ficheros: {0}  |  amenazas conocidas: {1}  |  sospechosos: {2}'
        beforePostFmt = 'protecciones ANTES: {0}'
        deltaLineFmt = 'antes{0}: {1}   /   despues: {2}'
        onFmt        = ' (sobre {0})'
        dlgFolder    = 'Carpeta del juego'
    }
    $en = @{
        title    = 'Game folder'
        intro    = 'The game folder is where the crack components live. Here I can (1) scan it for known components and cross-check with your protections, and (2) watch what the launch does to your defenses. Important: while the crack is actually running, its deepest part is invisible to me; my advantage is catching it before it starts, and the traces it leaves behind.'
        pathLbl  = 'Path of the game folder (or an .exe):'
        browse   = 'Browse...'
        btnAnalyze = 'Analyze this folder'
        analyzeH = 'Folder analysis'
        analyzing = 'Analyzing the folder (T7) and checking your protections (T1)...'
        noPath   = 'First choose a valid folder.'
        watchH   = 'Watch while you play (snapshot before / you play / snapshot after)'
        watchP   = 'HVGuard NEVER launches the game: YOU do. I only take a snapshot of your protections before and after to see if the launch turned them off.'
        btnBefore = 'Take snapshot BEFORE playing'
        btnAfter  = 'I closed the game -> snapshot AFTER'
        beforeOk  = 'BEFORE snapshot taken and SAVED (it survives a reboot). NOW launch the game YOURSELF (HVGuard does not); if the crack asks to reboot, do it. When you finish, open HVGuard and click "I closed the game".'
        pendingFmt = 'You have a saved BEFORE snapshot from {0}{1}. When you close the game, click "I closed the game" to compare.'
        afterRun  = 'Taking AFTER snapshot and comparing...'
        chkWatch  = 'Alert if new .sys/.cmd files appear in the folder while I watch'
        deltaBadH = 'The launch DEGRADED your defenses:'
        deltaOkH  = 'I did not detect the launch degrading your defenses.'
        deltaLimit = 'Honest limit: whatever the crack loads at the deepest level of your PC is invisible to me WHILE it is running. Not seeing a drop does not guarantee nothing happened; only that your key protections were still active in the after snapshot.'
        iocAppeared = 'A tracking mark the crack leaves behind appeared: a sign the technique was prepared or used.'
        corrCompromised = 'COMPROMISED state: this folder carries crack components AND your protections are weak. The bypass can establish itself.'
        corrComponents  = 'There are crack components in the folder, but your key protections (HVCI) are still active: it cannot load while you keep them. Consider Repair/Harden and deleting those components.'
        corrPostureBad  = 'I did not find known components in the folder, but your protections are weak. Go to "Repair" and "Harden".'
        corrClean       = 'I did not find known crack components in the folder and your key protections are active. (Not a guarantee of safety.)'
        newFileFmt = 'A new file appeared in the folder: {0}'
        never    = 'Remember: "clean" = "no known threats found", never "it is safe".'
        beforeNeeded = 'Take the BEFORE snapshot first.'
        watchOn  = 'Folder watch ACTIVE.'
        watchOff = 'Folder watch stopped.'
        regFmt       = 'before: PASS  ->  after: FAIL. {0}'
        countsFmt    = 'Files: {0}  |  known threats: {1}  |  suspicious: {2}'
        beforePostFmt = 'protections BEFORE: {0}'
        deltaLineFmt = 'before{0}: {1}   /   after: {2}'
        onFmt        = ' (on {0})'
        dlgFolder    = 'Game folder'
    }
    if ($Lang -eq 'en') { return $en } else { return $es }
}

function Get-HvgM4Delta {
    <# Compares two T1 JSON snapshots (before/after). Returns @{ Regressions=@(...); IocAppeared=bool }. #>
    param($Before, $After)
    $regs = @()
    # Localized regression line, with an English fallback so this stays usable standalone (tests).
    $regFmt = if ($script:HvgM4.S -and $script:HvgM4.S.regFmt) { $script:HvgM4.S.regFmt } else { 'before: PASS  ->  after: FAIL. {0}' }
    $mapBefore = @{}
    if ($Before -and $Before.checks) { foreach ($c in $Before.checks) { $mapBefore["$($c.id)"] = "$($c.status)" } }
    if ($After -and $After.checks) {
        foreach ($c in $After.checks) {
            $isCore = $false; try { $isCore = [bool]$c.core } catch { }
            if (-not $isCore) { continue }
            $b = $mapBefore["$($c.id)"]
            if ($b -eq 'PASS' -and "$($c.status)" -eq 'FAIL') {
                $regs += [pscustomobject]@{ id = $c.id; name = $c.name; detail = ($regFmt -f $c.evidence) }
            }
        }
    }
    $iocAppeared = $false
    try { $iocAppeared = ((-not [bool]$Before.iocDetected) -and [bool]$After.iocDetected) } catch { }
    return @{ Regressions = @($regs); IocAppeared = $iocAppeared }
}

function Get-HvgM4Correlation {
    <# Combines T7 (folder) and T1 (posture) into @{ Level; Text }. #>
    param($T7, $T1, $S)
    $t7o = if ($T7) { "$($T7.overall)" } else { '' }
    $t1o = if ($T1) { "$($T1.overall)" } else { '' }
    $hasComponents = ($t7o -eq 'KNOWN-THREAT')
    $postureBad = ($t1o -eq 'FAIL')
    if ($hasComponents -and $postureBad) { return @{ Level = 'bad'; Text = $S.corrCompromised } }
    if ($hasComponents) { return @{ Level = 'warn'; Text = $S.corrComponents } }
    if ($postureBad) { return @{ Level = 'warn'; Text = $S.corrPostureBad } }
    return @{ Level = 'ok'; Text = $S.corrClean }
}

function Get-HvgM4Path { if ($script:HvgM4.PathBox) { return ([string]$script:HvgM4.PathBox.Text).Trim() } return '' }

function Set-HvgM4ActionsEnabled {
    param([bool]$On)
    if ($script:HvgM4.BtnAnalyze) { $script:HvgM4.BtnAnalyze.IsEnabled = $On }
    if ($script:HvgM4.BtnBefore) { $script:HvgM4.BtnBefore.IsEnabled = $On }
    # "I closed the game" if there is a BEFORE snapshot in memory OR saved to disk (survives reboots).
    $hasBaseline = ($null -ne $script:HvgM4.Before) -or ($null -ne (Get-HvgBaseline))
    if ($script:HvgM4.BtnAfter) { $script:HvgM4.BtnAfter.IsEnabled = ($On -and $hasBaseline) }
}

function Show-HvgM4Analysis {
    param($T7, $T1)
    $s = $script:HvgM4.S
    $panel = $script:HvgM4.Results
    $panel.Children.Clear()
    [void]$panel.Children.Add((New-HvgHeading -Text $s.analyzeH))
    $corr = Get-HvgM4Correlation -T7 $T7 -T1 $T1 -S $s
    [void]$panel.Children.Add((New-HvgEvidenceCard -Level $corr.Level -Title $corr.Text -Detail ''))
    if ($T7 -and $T7.items) {
        foreach ($it in @($T7.items)) {
            if ("$($it.classification)" -eq 'CLEAN') { continue }
            $lvl = if ("$($it.classification)" -eq 'KNOWN-THREAT') { 'bad' } else { 'warn' }
            $sig = @($it.signals | Where-Object { "$($_.severity)" -ne 'info' } | ForEach-Object { $_.detail }) -join ' | '
            [void]$panel.Children.Add((New-HvgEvidenceCard -Level $lvl -Title ("[{0}] {1}" -f $it.classification, $it.name) -Detail ("{0}`n{1}" -f $it.path, $sig)))
        }
        $c = $T7.counts
        if ($c) { [void]$panel.Children.Add((New-HvgParagraph -Text ($s.countsFmt -f $c.scanned, $c.known, $c.suspect) -FontSize 12 -Color '#6B7280')) }
    }
    [void]$panel.Children.Add((New-HvgParagraph -Text $s.never -FontSize 12 -Color '#6B7280'))
}

function Invoke-HvgM4Analyze {
    # Async: T7 (folder scan, can take a while) -> T1 (posture) -> render. Does NOT block the window.
    $s = $script:HvgM4.S
    $path = Get-HvgM4Path
    $panel = $script:HvgM4.Results
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { $panel.Children.Clear(); [void]$panel.Children.Add((New-HvgParagraph -Text $s.noPath -Color '#D64545')); return }
    Set-HvgBusy -On $true -Text $s.analyzing
    Set-HvgM4ActionsEnabled $false
    $panel.Children.Clear()
    [void]$panel.Children.Add((New-HvgParagraph -Text $s.analyzing))
    Invoke-HvgToolAsync -ScriptName T7 -Params @{ Target = $path } -TimeoutSec 1800 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM4.S.analyzing, $sec) } `
        -OnDone {
        param($t7)
        $script:HvgM4._t7 = $t7
        Invoke-HvgToolAsync -ScriptName T1 -TimeoutSec 120 `
            -OnDone {
            param($t1)
            try { Show-HvgM4Analysis -T7 $script:HvgM4._t7.Result -T1 $t1.Result; Set-HvgStatusBar -Text $script:HvgM4.S.analyzeH }
            catch { Set-HvgStatusBar -Text ("M4: " + $_.Exception.Message) }
            finally { Set-HvgBusy -On $false -Text ''; Set-HvgM4ActionsEnabled $true }
        }
    }
}

function Invoke-HvgM4Before {
    # Async: posture snapshot (T1) BEFORE playing. The user launches the game on their own.
    $s = $script:HvgM4.S
    Set-HvgBusy -On $true -Text $s.watchH
    Set-HvgM4ActionsEnabled $false
    Invoke-HvgToolAsync -ScriptName T1 -TimeoutSec 120 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM4.S.watchH, $sec) } `
        -OnDone {
        param($t1)
        $s = $script:HvgM4.S
        try {
            $script:HvgM4.Before = $t1.Result
            # Persist to disk so it survives the reboot the crack requires (VBS.cmd -> reboot).
            [void](Save-HvgBaseline -Posture $t1.Result -Source 'manual' -TargetPath (Get-HvgM4Path))
            $panel = $script:HvgM4.Results; $panel.Children.Clear()
            [void]$panel.Children.Add((New-HvgEvidenceCard -Level info -Title $s.beforeOk -Detail ($s.beforePostFmt -f $(if ($t1.Result) { $t1.Result.overall } else { '?' }))))
            if ($script:HvgM4.ChkWatch -and $script:HvgM4.ChkWatch.IsChecked) { Start-HvgM4Watch }
            Set-HvgStatusBar -Text $s.beforeOk
        }
        catch { Set-HvgStatusBar -Text ("M4: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; Set-HvgM4ActionsEnabled $true }
    }
}

function Invoke-HvgM4After {
    $s = $script:HvgM4.S
    $hasBaseline = ($null -ne $script:HvgM4.Before) -or ($null -ne (Get-HvgBaseline))
    if (-not $hasBaseline) { [System.Windows.MessageBox]::Show($s.beforeNeeded, 'HVGuard', 'OK', 'Information') | Out-Null; return }
    # Async: posture snapshot (T1) AFTER and comparison. NEVER launches the game.
    Set-HvgBusy -On $true -Text $s.afterRun
    Set-HvgM4ActionsEnabled $false
    Stop-HvgM4Watch
    Invoke-HvgToolAsync -ScriptName T1 -TimeoutSec 120 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM4.S.afterRun, $sec) } `
        -OnDone {
        param($t1)
        $s = $script:HvgM4.S
        try {
            $after = $t1.Result
            # BEFORE snapshot: from memory, or from disk if we're coming back from a reboot (survives the crack's reboot)
            $before = $script:HvgM4.Before
            $beforeStamp = ''
            if (-not $before) { $bl = Get-HvgBaseline; if ($bl) { $before = $bl.posture; $beforeStamp = " ($($bl.timestampLocal))" } }
            $delta = Get-HvgM4Delta -Before $before -After $after
            $panel = $script:HvgM4.Results; $panel.Children.Clear()
            if ($delta.Regressions.Count -gt 0 -or $delta.IocAppeared) {
                [void]$panel.Children.Add((New-HvgParagraph -Text $s.deltaBadH -Color '#D64545'))
                foreach ($rg in $delta.Regressions) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level bad -Title ("{0} ({1})" -f $rg.name, $rg.id) -Detail $rg.detail)) }
                if ($delta.IocAppeared) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level bad -Title $s.iocAppeared -Detail '')) }
            }
            else {
                [void]$panel.Children.Add((New-HvgEvidenceCard -Level ok -Title $s.deltaOkH -Detail ''))
            }
            [void]$panel.Children.Add((New-HvgParagraph -Text ($s.deltaLineFmt -f $beforeStamp, $(if ($before) { $before.overall } else { '?' }), $(if ($after) { $after.overall } else { '?' })) -FontSize 12 -Color '#6B7280'))
            [void]$panel.Children.Add((New-HvgParagraph -Text $s.deltaLimit -FontSize 12 -Color '#6B7280'))
            $script:HvgM4.Before = $null
            Clear-HvgBaseline
            Set-HvgStatusBar -Text $s.watchH
        }
        catch { Set-HvgStatusBar -Text ("M4: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; Set-HvgM4ActionsEnabled $true }
    }
}

# --- Folder watch via polling (DispatcherTimer on the UI thread; without touching processes) ---------
function Get-HvgM4WatchSet {
    param([string]$Path)
    $set = @{}
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(sys|cmd|bat)$' })) {
            $set[$f.FullName] = $true
        }
    } catch { }
    return $set
}
function Start-HvgM4Watch {
    $path = Get-HvgM4Path
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return }
    Stop-HvgM4Watch
    $script:HvgM4.WatchBaseline = Get-HvgM4WatchSet -Path $path
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromSeconds(5)
    $timer.Add_Tick({
            try {
                $p = Get-HvgM4Path
                if (-not $p -or -not (Test-Path -LiteralPath $p)) { return }
                $now = Get-HvgM4WatchSet -Path $p
                foreach ($k in $now.Keys) {
                    if (-not $script:HvgM4.WatchBaseline.ContainsKey($k)) {
                        $script:HvgM4.WatchBaseline[$k] = $true
                        [void]$script:HvgM4.Results.Children.Add((New-HvgEvidenceCard -Level warn -Title ($script:HvgM4.S.newFileFmt -f (Split-Path $k -Leaf)) -Detail $k))
                    }
                }
            } catch { }
        })
    $timer.Start()
    $script:HvgM4.Watch = $timer
    Set-HvgStatusBar -Text $script:HvgM4.S.watchOn
}
function Stop-HvgM4Watch {
    if ($script:HvgM4.Watch) { try { $script:HvgM4.Watch.Stop() } catch { }; $script:HvgM4.Watch = $null }
}

function Invoke-HvgM4Browse {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dlg = [System.Windows.Forms.FolderBrowserDialog]::new()
        $dlg.Description = $script:HvgM4.S.dlgFolder
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            if ($script:HvgM4.PathBox) { $script:HvgM4.PathBox.Text = $dlg.SelectedPath }
        }
    } catch { }
}

function Initialize-HvgModule_M4Folder {
    param($Ctx)
    $panel = $Ctx.Window.FindName('PanelFolder')
    $panel.Children.Clear()
    Stop-HvgM4Watch
    $s = Get-HvgM4Strings -Lang $Ctx.Lang
    $script:HvgM4.S = $s
    $script:HvgM4.Panel = $panel
    $script:HvgM4.Before = $null

    $root = [System.Windows.Controls.StackPanel]::new()
    $root.Margin = [System.Windows.Thickness]::new(4)
    [void]$root.Children.Add((New-HvgHeading -Text $s.title))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.intro -FontSize 12 -Color '#6B7280'))

    # Path
    [void]$root.Children.Add((New-HvgParagraph -Text $s.pathLbl -FontSize 12))
    $pathRow = [System.Windows.Controls.StackPanel]::new()
    $pathRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $pathRow.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    $tb = [System.Windows.Controls.TextBox]::new()
    $tb.Width = 480; $tb.MinHeight = 26; $tb.VerticalContentAlignment = [System.Windows.VerticalAlignment]::Center
    $tb.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
    [void]$pathRow.Children.Add($tb)
    $script:HvgM4.PathBox = $tb
    $btnB = [System.Windows.Controls.Button]::new()
    $btnB.Content = $s.browse; $btnB.MinWidth = 90; $btnB.MinHeight = 28
    $btnB.Add_Click({ Invoke-HvgM4Browse })
    [void]$pathRow.Children.Add($btnB)
    [void]$root.Children.Add($pathRow)

    $btnA = [System.Windows.Controls.Button]::new()
    $btnA.Content = $s.btnAnalyze; $btnA.MinWidth = 170; $btnA.MinHeight = 38
    $btnA.FontWeight = [System.Windows.FontWeights]::SemiBold
    $btnA.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $btnA.Margin = [System.Windows.Thickness]::new(0, 0, 0, 14)
    $btnA.Add_Click({ Invoke-HvgM4Analyze })
    [void]$root.Children.Add($btnA)
    $script:HvgM4.BtnAnalyze = $btnA

    # Watch while playing
    [void]$root.Children.Add((New-HvgHeading -Text $s.watchH))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.watchP -FontSize 12 -Color '#6B7280'))
    $watchRow = [System.Windows.Controls.StackPanel]::new()
    $watchRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $watchRow.Margin = [System.Windows.Thickness]::new(0, 2, 0, 6)
    $btnBefore = [System.Windows.Controls.Button]::new()
    $btnBefore.Content = $s.btnBefore; $btnBefore.MinWidth = 200; $btnBefore.MinHeight = 38
    $btnBefore.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0)
    $btnBefore.Add_Click({ Invoke-HvgM4Before })
    [void]$watchRow.Children.Add($btnBefore)
    $script:HvgM4.BtnBefore = $btnBefore
    $btnAfter = [System.Windows.Controls.Button]::new()
    $btnAfter.Content = $s.btnAfter; $btnAfter.MinWidth = 220; $btnAfter.MinHeight = 38
    $btnAfter.IsEnabled = $false
    $btnAfter.Add_Click({ Invoke-HvgM4After })
    [void]$watchRow.Children.Add($btnAfter)
    $script:HvgM4.BtnAfter = $btnAfter
    [void]$root.Children.Add($watchRow)

    $chk = [System.Windows.Controls.CheckBox]::new()
    $chk.Content = $s.chkWatch
    $chk.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)
    [void]$root.Children.Add($chk)
    $script:HvgM4.ChkWatch = $chk

    [void]$root.Children.Add((New-HvgCopyAllButton -Label $Ctx.T.CopyAll -CopiedText $Ctx.T.Copied -GetContainer { $script:HvgM4.Results }))
    # The scroll comes from the tab's ScrollViewer (Shell.xaml); here it's just a StackPanel that grows.
    $results = [System.Windows.Controls.StackPanel]::new()
    [void]$root.Children.Add($results)
    $script:HvgM4.Results = $results

    # BEFORE snapshot saved from a previous session (e.g. after the reboot the crack requires): warn
    # and allow comparing even if HVGuard was closed/restarted.
    $bl = Get-HvgBaseline
    if ($bl) {
        $tgt = if ($bl.targetPath) { ($s.onFmt -f $bl.targetPath) } else { '' }
        [void]$results.Children.Add((New-HvgEvidenceCard -Level info -Title ($s.pendingFmt -f $bl.timestampLocal, $tgt) -Detail ''))
    }
    Set-HvgM4ActionsEnabled $true

    [void]$panel.Children.Add($root)
}
