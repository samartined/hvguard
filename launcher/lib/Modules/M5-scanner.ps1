# =====================================================================================================
#  HVGuard - Module M5: Known-threat scanner (wraps T7)  [READ ONLY]
#  Two modes (plan 06 section 6.5):
#    - Pre-install (limited): over the installer/.exe -> only the "shell". MANDATORY blind-spot
#      banner (section 5.4): the payload is encrypted and is not visible until installed.
#    - Post-install (the useful one): over the already-extracted folder -> full scan.
#  OPT-IN checkbox "online reputation (hash only)" off by default.
#  NEVER executes the target: it only scans it statically. Always available (does not require admin).
#  Contract: defines Initialize-HvgModule_M5Scanner($Ctx).
# =====================================================================================================

$script:HvgM5 = @{ Panel = $null; PathBox = $null; Results = $null; Banner = $null; S = $null
    ChkOnline = $null; RbPre = $null; RbPost = $null; BtnAnalyze = $null
}

function Get-HvgM5Strings {
    param([string]$Lang)
    $es = @{
        title    = 'Escaner de amenazas conocidas'
        intro    = 'Busca en un fichero o carpeta componentes conocidos del crack comparando huellas digitales, nombres, firmas digitales y patrones conocidos. Detecta amenazas conocidas y desviaciones de integridad; NO es un antivirus ni una garantia.'
        modePre  = 'Pre-instalacion (el instalador / .exe) - limitado'
        modePost = 'Post-instalacion (la carpeta del juego ya instalada) - recomendado'
        pathLbl  = 'Ruta a analizar:'
        browse   = 'Elegir...'
        btnAnalyze = 'Analizar'
        chkOnline = 'Tambien consultar este fichero online (apagado por defecto; solo envio una huella digital, nunca el fichero)'
        analyzing = 'Analizando (T7)...'
        noPath   = 'Primero elige una ruta valida.'
        blind    = 'No puedo ver lo que va cifrado dentro del instalador hasta que se instala. Un resultado "limpio" aqui NO significa que el crack sea seguro. Analiza la carpeta del juego YA INSTALADO, antes de jugar.'
        postHint = 'Modo recomendado: analiza la carpeta ya extraida, donde si viven los componentes del crack.'
        cleanH   = 'No he encontrado amenazas conocidas (esto no es una garantia).'
        suspectH = 'He encontrado senales que deberias revisar:'
        knownH   = 'Coincide con una amenaza conocida:'
        errH     = 'No se pudo completar el analisis.'
        countsFmt = 'Ficheros: {0}  |  amenazas conocidas: {1}  |  sospechosos: {2}  |  limpios: {3}'
        truncated = 'Aviso: se alcanzo el limite de ficheros; el analisis no cubrio toda la carpeta.'
        dlgFile   = 'Instalador / ejecutable'
        dlgFolder = 'Carpeta del juego instalada'
        never    = 'Recuerda: "limpio" = "no encontre amenazas conocidas", nunca "es seguro".'
    }
    $en = @{
        title    = 'Known-threat scanner'
        intro    = 'Searches a file or folder for known crack components by matching file fingerprints, names, digital signatures and known patterns. It detects known threats and integrity deviations; it is NOT an antivirus nor a guarantee.'
        modePre  = 'Pre-install (the installer / .exe) - limited'
        modePost = 'Post-install (the already-installed game folder) - recommended'
        pathLbl  = 'Path to analyze:'
        browse   = 'Browse...'
        btnAnalyze = 'Analyze'
        chkOnline = 'Also check this file online (off by default; only sends a fingerprint, never the file)'
        analyzing = 'Analyzing (T7)...'
        noPath   = 'First choose a valid path.'
        blind    = 'I cannot see what is encrypted inside the installer until it is installed. A "clean" result here does NOT mean the crack is safe. Scan the ALREADY-INSTALLED game folder, before playing.'
        postHint = 'Recommended mode: scan the already-extracted folder, where the crack components actually live.'
        cleanH   = 'No known threats found (this is not a guarantee).'
        suspectH = 'I found signals you should review:'
        knownH   = 'Matches a known threat:'
        errH     = 'The analysis could not be completed.'
        countsFmt = 'Files: {0}  |  known threats: {1}  |  suspicious: {2}  |  clean: {3}'
        truncated = 'Warning: the file limit was reached; the scan did not cover the whole folder.'
        dlgFile   = 'Installer / executable'
        dlgFolder = 'Installed game folder'
        never    = 'Remember: "clean" = "no known threats found", never "it is safe".'
    }
    if ($Lang -eq 'en') { return $en } else { return $es }
}

function Test-HvgM5PreMode { return ($script:HvgM5.RbPre -and $script:HvgM5.RbPre.IsChecked) }

function Update-HvgM5Banner {
    $s = $script:HvgM5.S
    $b = $script:HvgM5.Banner
    if (-not $b) { return }
    $b.Children.Clear()
    if (Test-HvgM5PreMode) {
        [void]$b.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.blind -Detail ''))
    }
    else {
        [void]$b.Children.Add((New-HvgEvidenceCard -Level info -Title $s.postHint -Detail ''))
    }
}

function Invoke-HvgM5Browse {
    $s = $script:HvgM5.S
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        if (Test-HvgM5PreMode) {
            $dlg = [System.Windows.Forms.OpenFileDialog]::new()
            $dlg.Title = $script:HvgM5.S.dlgFile
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:HvgM5.PathBox.Text = $dlg.FileName }
        }
        else {
            $dlg = [System.Windows.Forms.FolderBrowserDialog]::new()
            $dlg.Description = $script:HvgM5.S.dlgFolder
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:HvgM5.PathBox.Text = $dlg.SelectedPath }
        }
    } catch { }
}

function Show-HvgM5Result {
    param($R)
    $s = $script:HvgM5.S
    $panel = $script:HvgM5.Results
    $panel.Children.Clear()
    $res = $R.Result
    if (-not $res -or "$($res.overall)" -eq 'ERROR' -or $R.TimedOut) {
        $why = if ($R.TimedOut) { 'timeout' } elseif ($res -and $res.error) { "$($res.error)" } elseif ($R.Error) { $R.Error } else { '' }
        [void]$panel.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.errH -Detail $why))
        return
    }
    $overall = "$($res.overall)"
    $hdr = switch ($overall) { 'KNOWN-THREAT' { $s.knownH } 'SUSPECT-SIGNALS' { $s.suspectH } default { $s.cleanH } }
    $hdrColor = switch ($overall) { 'KNOWN-THREAT' { '#D64545' } 'SUSPECT-SIGNALS' { '#B45309' } default { '#15803D' } }
    [void]$panel.Children.Add((New-HvgParagraph -Text $hdr -Color $hdrColor))
    foreach ($it in @($res.items)) {
        if ("$($it.classification)" -eq 'CLEAN') { continue }
        $lvl = if ("$($it.classification)" -eq 'KNOWN-THREAT') { 'bad' } else { 'warn' }
        $sig = @($it.signals | Where-Object { "$($_.severity)" -ne 'info' } | ForEach-Object { $_.detail }) -join ' | '
        [void]$panel.Children.Add((New-HvgEvidenceCard -Level $lvl -Title ("[{0}] {1}" -f $it.classification, $it.name) -Detail ("{0}`n{1}" -f $it.path, $sig)))
    }
    $c = $res.counts
    if ($c) {
        [void]$panel.Children.Add((New-HvgParagraph -Text ($s.countsFmt -f $c.scanned, $c.known, $c.suspect, $c.clean) -FontSize 12 -Color '#6B7280'))
        $trunc = $false; try { $trunc = [bool]$c.truncated } catch { }
        if ($trunc) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.truncated -Detail '')) }
    }
    [void]$panel.Children.Add((New-HvgParagraph -Text $s.never -FontSize 12 -Color '#6B7280'))
}

function Invoke-HvgM5Scan {
    # Async: T7 over the target. Does NOT block the window; shows elapsed seconds.
    $s = $script:HvgM5.S
    $path = ([string]$script:HvgM5.PathBox.Text).Trim()
    $panel = $script:HvgM5.Results
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { $panel.Children.Clear(); [void]$panel.Children.Add((New-HvgParagraph -Text $s.noPath -Color '#D64545')); return }
    $params = @{ Target = $path }
    if ($script:HvgM5.ChkOnline -and $script:HvgM5.ChkOnline.IsChecked) { $params['OnlineHashLookup'] = $true }
    Set-HvgBusy -On $true -Text $s.analyzing
    if ($script:HvgM5.BtnAnalyze) { $script:HvgM5.BtnAnalyze.IsEnabled = $false }
    $panel.Children.Clear()
    [void]$panel.Children.Add((New-HvgParagraph -Text $s.analyzing))
    Invoke-HvgToolAsync -ScriptName T7 -Params $params -TimeoutSec 1800 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM5.S.analyzing, $sec) } `
        -OnDone {
        param($r)
        try { Show-HvgM5Result -R $r; Set-HvgStatusBar -Text $script:HvgM5.S.title }
        catch { Set-HvgStatusBar -Text ("M5: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; if ($script:HvgM5.BtnAnalyze) { $script:HvgM5.BtnAnalyze.IsEnabled = $true } }
    }
}

function Initialize-HvgModule_M5Scanner {
    param($Ctx)
    $panel = $Ctx.Window.FindName('PanelScanner')
    $panel.Children.Clear()
    $s = Get-HvgM5Strings -Lang $Ctx.Lang
    $script:HvgM5.S = $s
    $script:HvgM5.Panel = $panel

    $root = [System.Windows.Controls.StackPanel]::new()
    $root.Margin = [System.Windows.Thickness]::new(4)
    [void]$root.Children.Add((New-HvgHeading -Text $s.title))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.intro -FontSize 12 -Color '#6B7280'))

    # Mode
    $rbPost = [System.Windows.Controls.RadioButton]::new()
    $rbPost.Content = $s.modePost; $rbPost.IsChecked = $true; $rbPost.Margin = [System.Windows.Thickness]::new(0, 2, 0, 2)
    $rbPre = [System.Windows.Controls.RadioButton]::new()
    $rbPre.Content = $s.modePre; $rbPre.Margin = [System.Windows.Thickness]::new(0, 2, 0, 6)
    $rbPost.Add_Checked({ Update-HvgM5Banner })
    $rbPre.Add_Checked({ Update-HvgM5Banner })
    [void]$root.Children.Add($rbPost)
    [void]$root.Children.Add($rbPre)
    $script:HvgM5.RbPre = $rbPre
    $script:HvgM5.RbPost = $rbPost

    # Banner (blind spot / hint) - filled in based on mode
    $banner = [System.Windows.Controls.StackPanel]::new()
    [void]$root.Children.Add($banner)
    $script:HvgM5.Banner = $banner

    # Path
    [void]$root.Children.Add((New-HvgParagraph -Text $s.pathLbl -FontSize 12))
    $pathRow = [System.Windows.Controls.StackPanel]::new()
    $pathRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $pathRow.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    $tb = [System.Windows.Controls.TextBox]::new()
    $tb.Width = 470; $tb.MinHeight = 26; $tb.VerticalContentAlignment = [System.Windows.VerticalAlignment]::Center
    $tb.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
    [void]$pathRow.Children.Add($tb)
    $script:HvgM5.PathBox = $tb
    $btnB = [System.Windows.Controls.Button]::new()
    $btnB.Content = $s.browse; $btnB.MinWidth = 90; $btnB.MinHeight = 28
    $btnB.Add_Click({ Invoke-HvgM5Browse })
    [void]$pathRow.Children.Add($btnB)
    [void]$root.Children.Add($pathRow)

    # Opt-in online reputation (off by default)
    $chk = [System.Windows.Controls.CheckBox]::new()
    $chk.Content = $s.chkOnline; $chk.IsChecked = $false
    $chk.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    [void]$root.Children.Add($chk)
    $script:HvgM5.ChkOnline = $chk

    $btnA = [System.Windows.Controls.Button]::new()
    $btnA.Content = $s.btnAnalyze; $btnA.MinWidth = 140; $btnA.MinHeight = 38
    $btnA.FontWeight = [System.Windows.FontWeights]::SemiBold
    $btnA.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $btnA.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)
    $btnA.Add_Click({ Invoke-HvgM5Scan })
    [void]$root.Children.Add($btnA)
    $script:HvgM5.BtnAnalyze = $btnA

    [void]$root.Children.Add((New-HvgCopyAllButton -Label $Ctx.T.CopyAll -CopiedText $Ctx.T.Copied -GetContainer { $script:HvgM5.Results }))
    # The scroll comes from the tab's ScrollViewer (Shell.xaml); here it's just a StackPanel that grows.
    $results = [System.Windows.Controls.StackPanel]::new()
    [void]$root.Children.Add($results)
    $script:HvgM5.Results = $results

    [void]$panel.Children.Add($root)
    Update-HvgM5Banner
}
