# =====================================================================================================
#  HVGuard - lib/UI.ps1
#  WPF helpers shared by HVGuard.ps1 and the modules: paint the global status light, build evidence
#  cards, refresh the UI during synchronous calls to the engine, etc. It does NOT know about the
#  engine or the verdicts: it only draws what it is given. It is dot-sourced into HVGuard's scope;
#  it keeps the context in $script:HvgCtx via Initialize-HvgUI.
# =====================================================================================================

$script:HvgCtx = $null

# Status-light palette (global state -> color).
$script:HvgStatusColor = @{
    Protected   = '#22A559'   # green
    AtRisk      = '#E8A317'   # amber
    Compromised = '#D64545'   # red
    Working     = '#2F6FED'   # blue (in progress)
    Unknown     = '#9AA0A6'   # gray
    NotChecked  = '#9AA0A6'   # gray
}
# Color of the evidence card's side accent, by level.
$script:HvgLevelColor = @{
    ok   = '#22A559'
    warn = '#E8A317'
    bad  = '#D64545'
    info = '#6B7280'
}

function Initialize-HvgUI {
    param([Parameter(Mandatory)]$Ctx)
    $script:HvgCtx = $Ctx
}

function New-HvgBrush {
    param([Parameter(Mandatory)][string]$Hex)
    $color = [System.Windows.Media.ColorConverter]::ConvertFromString($Hex)
    return [System.Windows.Media.SolidColorBrush]::new($color)
}

function New-HvgSelectableText {
    <#
    .SYNOPSIS  SELECTABLE, copyable text (borderless, transparent, read-only TextBox).
               Lets the user select and copy (native "Copy" menu / Ctrl+C) paths, hashes, threat names,
               etc. to investigate them. WPF does not allow selecting the text of a TextBlock; that is
               why a read-only TextBox styled to look like a label is used here instead.
    #>
    param([string]$Text, [bool]$Bold = $false, [string]$Color = '#374151', [double]$FontSize = 13)
    $tb = [System.Windows.Controls.TextBox]::new()
    $tb.Text = [string]$Text
    $tb.IsReadOnly = $true
    $tb.IsReadOnlyCaretVisible = $false
    $tb.BorderThickness = [System.Windows.Thickness]::new(0)
    $tb.Background = [System.Windows.Media.Brushes]::Transparent
    $tb.Padding = [System.Windows.Thickness]::new(0)
    $tb.Margin = [System.Windows.Thickness]::new(0)
    $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $tb.Foreground = (New-HvgBrush $Color)
    $tb.FontSize = $FontSize
    $tb.IsTabStop = $false
    $tb.Cursor = [System.Windows.Input.Cursors]::IBeam
    $tb.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Stretch
    if ($Bold) { $tb.FontWeight = [System.Windows.FontWeights]::SemiBold }
    return $tb
}

function Copy-HvgToClipboard {
    param([string]$Text)
    try { [System.Windows.Clipboard]::SetText([string]$Text) } catch { }
}

function Get-HvgElementText {
    <# Text of a WPF subtree (recursive): concatenates the .Text of TextBox/TextBlock in order. #>
    param($El)
    if ($null -eq $El) { return '' }
    if ($El -is [System.Windows.Controls.TextBox]) { return [string]$El.Text }
    if ($El -is [System.Windows.Controls.TextBlock]) { return [string]$El.Text }
    $parts = @()
    foreach ($c in [System.Windows.LogicalTreeHelper]::GetChildren($El)) {
        if ($c -is [System.Windows.DependencyObject]) {
            $t = Get-HvgElementText -El $c
            if ($t -and $t.Trim()) { $parts += $t }
        }
    }
    return ($parts -join "`r`n")
}

function Get-HvgContainerText {
    <#
    .SYNOPSIS  Extracts ALL the text from a results container (a StackPanel with cards/paragraphs, or
               the status-light ItemsControl) as a plain-text report, with a blank line between
               blocks. Used for "Copy all".
    #>
    param($Container)
    if ($null -eq $Container) { return '' }
    $items = @()
    if ($Container -is [System.Windows.Controls.ItemsControl]) { $items = @($Container.Items) }
    elseif ($null -ne $Container.Children) { $items = @($Container.Children) }
    $blocks = [System.Collections.Generic.List[string]]::new()
    foreach ($child in $items) {
        if ($child -is [System.Windows.DependencyObject]) {
            $t = Get-HvgElementText -El $child
            if ($t -and $t.Trim()) { $blocks.Add($t) }
        }
    }
    return ($blocks -join "`r`n`r`n")
}

function New-HvgCopyAllButton {
    <#
    .SYNOPSIS  "Copy all" button that copies to the clipboard the text of the container returned by &$GetContainer.
    .PARAMETER Label        Button text.
    .PARAMETER CopiedText   Status-bar message after copying.
    .PARAMETER GetContainer Scriptblock that returns the container (StackPanel/ItemsControl) to copy.
    #>
    param([string]$Label, [string]$CopiedText, [Parameter(Mandatory)][scriptblock]$GetContainer)
    $btn = [System.Windows.Controls.Button]::new()
    $btn.Content = $Label
    $btn.MinWidth = 110; $btn.MinHeight = 26
    $btn.Padding = [System.Windows.Thickness]::new(10, 2, 10, 2)
    $btn.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $btn.Margin = [System.Windows.Thickness]::new(0, 4, 0, 6)
    # We store the getter and the message in Tag so we do not depend on local-variable capture.
    $btn.Tag = [pscustomobject]@{ Getter = $GetContainer; Copied = $CopiedText }
    $btn.Add_Click({
            try {
                $info = $this.Tag
                $txt = Get-HvgContainerText -Container (& $info.Getter)
                Copy-HvgToClipboard $txt
                if ($info.Copied) { Set-HvgStatusBar -Text $info.Copied }
            } catch { }
        })
    return $btn
}

function Invoke-HvgUIRefresh {
    <# Pumps the dispatcher so the UI (e.g. "Checking...") gets painted before a synchronous,
       blocking call to the engine. #>
    param()
    if (-not $script:HvgCtx) { return }
    try {
        $script:HvgCtx.Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch { }
}

function Set-HvgBusy {
    param([bool]$On, [string]$Text)
    if (-not $script:HvgCtx) { return }
    try {
        # AppStarting (arrow + hourglass) instead of Wait: signals "working" but the app stays usable
        # (with asynchronous execution the window does NOT freeze; you can still scroll / switch tabs).
        [System.Windows.Input.Mouse]::OverrideCursor = if ($On) { [System.Windows.Input.Cursors]::AppStarting } else { $null }
        if ($Text) { Set-HvgStatusBar -Text $Text }
        Invoke-HvgUIRefresh
    } catch { }
}

function Set-HvgStatusBar {
    param([string]$Text)
    if (-not $script:HvgCtx) { return }
    try { $script:HvgCtx.Window.FindName('StatusBar').Text = $Text } catch { }
}

function Set-HvgStatus {
    <#
    .SYNOPSIS  Paints the global status light (light + title) from a state key and a hint text.
    .PARAMETER State  Protected | AtRisk | Compromised | Working | Unknown | NotChecked
    .PARAMETER Hint   Plain-language sentence under the title (optional).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Protected','AtRisk','Compromised','Working','Unknown','NotChecked')][string]$State,
        [string]$Hint
    )
    if (-not $script:HvgCtx) { return }
    $win = $script:HvgCtx.Window
    $t   = $script:HvgCtx.T
    try {
        $win.FindName('StatusLight').Fill = New-HvgBrush $script:HvgStatusColor[$State]
        $label = if ($t -and $t.Status -and $t.Status[$State]) { $t.Status[$State] } else { $State }
        $win.FindName('StatusText').Text = $label
        if ($PSBoundParameters.ContainsKey('Hint')) {
            $win.FindName('StatusHint').Text = $Hint
        }
    } catch { }
}

function Clear-HvgDetails {
    if (-not $script:HvgCtx) { return }
    try {
        $ic = $script:HvgCtx.Window.FindName('DetailsContent')
        $ic.Items.Clear()
    } catch { }
}

function Set-HvgDetails {
    <# Replaces the details expander's content with the given cards. Auto-expands if there is anything. #>
    param([object[]]$Cards)
    if (-not $script:HvgCtx) { return }
    try {
        $win = $script:HvgCtx.Window
        $ic  = $win.FindName('DetailsContent')
        $ic.Items.Clear()
        if ($Cards) { foreach ($c in $Cards) { if ($c) { [void]$ic.Items.Add($c) } } }
        $win.FindName('DetailsExpander').IsExpanded = ([bool]$Cards -and @($Cards).Count -gt 0)
    } catch { }
}

function New-HvgEvidenceCard {
    <#
    .SYNOPSIS  Builds a uniform evidence card (Border) for the details expander or for the module
               panels.
    .PARAMETER Level  ok | warn | bad | info  (color of the side accent)
    .PARAMETER Title  Bold title.
    .PARAMETER Detail Explanatory text (wraps).
    #>
    param(
        [ValidateSet('ok','warn','bad','info')][string]$Level = 'info',
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = ''
    )
    $border = [System.Windows.Controls.Border]::new()
    $border.Background      = New-HvgBrush '#F9FAFB'
    $border.BorderBrush     = New-HvgBrush '#E5E7EB'
    $border.BorderThickness = [System.Windows.Thickness]::new(1)
    $border.CornerRadius    = [System.Windows.CornerRadius]::new(4)
    $border.Margin          = [System.Windows.Thickness]::new(0, 0, 0, 6)

    $row = [System.Windows.Controls.StackPanel]::new()
    $row.Orientation = [System.Windows.Controls.Orientation]::Horizontal

    $accent = [System.Windows.Controls.Border]::new()
    $accent.Width        = 5
    $accent.Background    = New-HvgBrush $script:HvgLevelColor[$Level]
    $accent.CornerRadius  = [System.Windows.CornerRadius]::new(4, 0, 0, 4)

    $content = [System.Windows.Controls.StackPanel]::new()
    $content.Margin = [System.Windows.Thickness]::new(10, 8, 10, 8)

    $tb = New-HvgSelectableText -Text $Title -Bold $true -Color '#111827' -FontSize 13
    [void]$content.Children.Add($tb)

    if ($Detail) {
        $dt = New-HvgSelectableText -Text $Detail -Color '#6B7280' -FontSize 12
        $dt.Margin = [System.Windows.Thickness]::new(0, 2, 0, 0)
        [void]$content.Children.Add($dt)
    }

    # The accent must stretch to the height of the content: wrap it in a 2-column Grid.
    $grid = [System.Windows.Controls.Grid]::new()
    $c0 = [System.Windows.Controls.ColumnDefinition]::new(); $c0.Width = [System.Windows.GridLength]::Auto
    $c1 = [System.Windows.Controls.ColumnDefinition]::new(); $c1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    [void]$grid.ColumnDefinitions.Add($c0)
    [void]$grid.ColumnDefinitions.Add($c1)
    [System.Windows.Controls.Grid]::SetColumn($accent, 0)
    [System.Windows.Controls.Grid]::SetColumn($content, 1)
    [void]$grid.Children.Add($accent)
    [void]$grid.Children.Add($content)

    # "Copy" context menu to copy the whole finding (name + detail) in one go.
    $en = ($script:HvgCtx -and $script:HvgCtx.Lang -eq 'en')
    $menu = [System.Windows.Controls.ContextMenu]::new()
    $mi = [System.Windows.Controls.MenuItem]::new()
    $mi.Header = if ($en) { 'Copy' } else { 'Copiar' }
    $mi.Tag = ($Title + $(if ($Detail) { "`n" + $Detail } else { '' }))
    $mi.Add_Click({ Copy-HvgToClipboard ([string]$this.Tag) })
    [void]$menu.Items.Add($mi)
    $border.ContextMenu = $menu
    $border.ToolTip = if ($en) { 'Select the text or right-click -> Copy' } else { 'Selecciona el texto o clic derecho -> Copiar' }

    $border.Child = $grid
    return $border
}

function New-HvgBadge {
    <# Small badge (e.g. "Restart needed", "Recommended"). #>
    param([Parameter(Mandatory)][string]$Text, [string]$Fg = '#92400E', [string]$Bg = '#FEF3C7')
    $b = [System.Windows.Controls.Border]::new()
    $b.Background      = New-HvgBrush $Bg
    $b.CornerRadius    = [System.Windows.CornerRadius]::new(3)
    $b.Padding         = [System.Windows.Thickness]::new(6, 1, 6, 1)
    $b.Margin          = [System.Windows.Thickness]::new(0, 0, 5, 0)
    $b.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $t = [System.Windows.Controls.TextBlock]::new()
    $t.Text = $Text; $t.FontSize = 10.5; $t.Foreground = New-HvgBrush $Fg
    $t.FontWeight = [System.Windows.FontWeights]::SemiBold
    $b.Child = $t
    return $b
}

function New-HvgStepChoice {
    <#
    .SYNOPSIS  SELECTABLE card for a repair step, built as three layers of progressive disclosure.
    .DESCRIPTION
               The user decides WHAT gets restored; to decide with good judgment they need to
               UNDERSTAND each item, which is why the explanation travels inside the option itself
               instead of in a separate manual.

               Three layers, because two different readers use the same screen:

                 Layer 1  -Title + -Badges       Always visible. Plain words only: no jargon and no
                                                 acronyms. Says what the user GETS, not how it works.
                 Layer 2  -What  ("What is this?")   Collapsed. The analogy, why it matters to them,
                                                 where they can see the same setting in Windows itself,
                                                 and what will be changed.
                 Layer 3  -Tech  ("Technical detail") Collapsed. Registry values, security properties,
                                                 event IDs. Kept because the forensic detail is
                                                 valuable - just off the lay reading path.

               -Detail is the actual measured state on this machine and stays visible under the
               dropdowns. Both dropdowns are omitted entirely when their text is empty.
               tools/check-plain-language.ps1 enforces the per-layer vocabulary budget.
    .OUTPUTS   [pscustomobject] @{ Id; Element; Check }  -> $_.Check.IsChecked = the user's choice.
    .OUTPUTS   [pscustomobject] @{ Id; Element; Check }  -> $_.Check.IsChecked = the user's choice.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [string]$What = '',
        [string]$Tech = '',
        [string]$Detail = '',
        [bool]$Checked = $true,
        [bool]$Enabled = $true,
        [string[]]$Badges = @(),
        [ValidateSet('ok','warn','bad','info')][string]$Level = 'warn',
        [string]$WhatLabel = 'What is this?',
        [string]$TechLabel = 'Technical detail'
    )
    $border = [System.Windows.Controls.Border]::new()
    $border.Background      = New-HvgBrush '#FFFFFF'
    $border.BorderBrush     = New-HvgBrush '#E5E7EB'
    $border.BorderThickness = [System.Windows.Thickness]::new(1)
    $border.CornerRadius    = [System.Windows.CornerRadius]::new(4)
    $border.Margin          = [System.Windows.Thickness]::new(0, 0, 0, 8)

    $accent = [System.Windows.Controls.Border]::new()
    $accent.Width       = 5
    $accent.Background  = New-HvgBrush $script:HvgLevelColor[$Level]
    $accent.CornerRadius = [System.Windows.CornerRadius]::new(4, 0, 0, 4)

    $content = [System.Windows.Controls.StackPanel]::new()
    $content.Margin = [System.Windows.Thickness]::new(10, 8, 10, 8)

    # Checkbox + title (the title goes INSIDE the CheckBox so the text itself is clickable).
    $chk = [System.Windows.Controls.CheckBox]::new()
    $chk.IsChecked  = $Checked
    $chk.IsEnabled  = $Enabled
    $chk.Tag        = $Id
    $chk.VerticalContentAlignment = [System.Windows.VerticalAlignment]::Center
    $lbl = [System.Windows.Controls.TextBlock]::new()
    $lbl.Text = $Title
    $lbl.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $lbl.FontWeight = [System.Windows.FontWeights]::SemiBold
    $lbl.FontSize = 13
    $lbl.Foreground = New-HvgBrush '#111827'
    $chk.Content = $lbl
    [void]$content.Children.Add($chk)

    if ($Badges -and $Badges.Count -gt 0) {
        $bp = [System.Windows.Controls.StackPanel]::new()
        $bp.Orientation = [System.Windows.Controls.Orientation]::Horizontal
        $bp.Margin = [System.Windows.Thickness]::new(22, 5, 0, 0)
        foreach ($bd in $Badges) { if ($bd) { [void]$bp.Children.Add((New-HvgBadge -Text $bd)) } }
        [void]$content.Children.Add($bp)
    }

    # Layer 2 - "What is this?": the plain-language explanation. Collapsed so as not to overwhelm.
    if ($What) {
        $exp = [System.Windows.Controls.Expander]::new()
        $exp.Header = $WhatLabel
        $exp.FontSize = 12
        $exp.Margin = [System.Windows.Thickness]::new(22, 6, 0, 0)
        $exp.Foreground = New-HvgBrush '#1D4ED8'
        $wt = New-HvgSelectableText -Text $What -Color '#374151' -FontSize 12
        $wt.Margin = [System.Windows.Thickness]::new(2, 4, 0, 2)
        $exp.Content = $wt
        [void]$content.Children.Add($exp)
    }

    # Layer 3 - "Technical detail": registry values, security properties, event IDs. Deliberately a
    # separate, quieter dropdown so the jargon never sits on the lay reading path, while the forensic
    # detail stays one click away for whoever wants it.
    if ($Tech) {
        $texp = [System.Windows.Controls.Expander]::new()
        $texp.Header = $TechLabel
        $texp.FontSize = 11.5
        $texp.Margin = [System.Windows.Thickness]::new(22, 2, 0, 0)
        $texp.Foreground = New-HvgBrush '#6B7280'
        $tt = New-HvgSelectableText -Text $Tech -Color '#6B7280' -FontSize 11.5
        $tt.Margin = [System.Windows.Thickness]::new(2, 4, 0, 2)
        $tt.FontFamily = [System.Windows.Media.FontFamily]::new('Consolas, Courier New, monospace')
        $texp.Content = $tt
        [void]$content.Children.Add($texp)
    }

    if ($Detail) {
        $dt = New-HvgSelectableText -Text $Detail -Color '#6B7280' -FontSize 11.5
        $dt.Margin = [System.Windows.Thickness]::new(22, 6, 0, 0)
        [void]$content.Children.Add($dt)
    }

    $grid = [System.Windows.Controls.Grid]::new()
    $c0 = [System.Windows.Controls.ColumnDefinition]::new(); $c0.Width = [System.Windows.GridLength]::Auto
    $c1 = [System.Windows.Controls.ColumnDefinition]::new(); $c1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    [void]$grid.ColumnDefinitions.Add($c0)
    [void]$grid.ColumnDefinitions.Add($c1)
    [System.Windows.Controls.Grid]::SetColumn($accent, 0)
    [System.Windows.Controls.Grid]::SetColumn($content, 1)
    [void]$grid.Children.Add($accent)
    [void]$grid.Children.Add($content)
    $border.Child = $grid

    return [pscustomobject]@{ Id = $Id; Element = $border; Check = $chk }
}

function New-HvgHeading {
    param([Parameter(Mandatory)][string]$Text)
    $tb = [System.Windows.Controls.TextBlock]::new()
    $tb.Text = $Text
    $tb.FontSize = 15
    $tb.FontWeight = [System.Windows.FontWeights]::SemiBold
    $tb.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6)
    $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
    return $tb
}

function New-HvgParagraph {
    param([Parameter(Mandatory)][string]$Text, [string]$Color = '#374151', [double]$FontSize = 13)
    # Selectable/copyable (read-only TextBox styled to look like a label).
    $tb = New-HvgSelectableText -Text $Text -Color $Color -FontSize $FontSize
    $tb.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    return $tb
}

# =====================================================================================================
#  ASYNCHRONOUS execution of the engine (does not block the UI thread)
#  The heavy work already lives in the child process (Start-HvgTool). Here we only POLL for its end
#  with a DispatcherTimer on the UI thread: the window stays alive (move it, scroll, switch tabs) and
#  we show the elapsed seconds. When it finishes, -OnDone is called on the UI thread with the same
#  object that Invoke-HvgTool returns. The tick is a scriptblock with the id "baked in" so it does not
#  depend on local-variable capture (fragile in WPF handlers); the state lives in $script:HvgAsyncOps.
# =====================================================================================================
$script:HvgAsyncOps = @{}

function Invoke-HvgToolAsync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [hashtable]$Params,
        [int]$TimeoutSec = 600,
        [Parameter(Mandatory)][scriptblock]$OnDone,
        [scriptblock]$OnTick
    )
    $h = Start-HvgTool -ScriptName $ScriptName -Params $Params
    if (-not $h.Started) {
        try { & $OnDone (Complete-HvgTool -Handle $h) } catch { }
        return
    }
    $id = [Guid]::NewGuid().ToString('N')
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(300)
    $script:HvgAsyncOps[$id] = @{ Handle = $h; OnDone = $OnDone; OnTick = $OnTick; Timer = $timer; TimeoutSec = $TimeoutSec }
    $timer.Add_Tick([ScriptBlock]::Create("Step-HvgAsyncOp '$id'"))
    $timer.Start()
}

function Step-HvgAsyncOp {
    param([string]$Id)
    $op = $script:HvgAsyncOps[$Id]
    if (-not $op) { return }
    $h = $op.Handle
    $elapsed = 0; try { $elapsed = [int]$h.Sw.Elapsed.TotalSeconds } catch { }
    $finished = $false; $timedOut = $false
    try { $finished = [bool]$h.Proc.HasExited } catch { $finished = $true }
    if (-not $finished -and $elapsed -ge $op.TimeoutSec) { $timedOut = $true; $finished = $true }

    if (-not $finished) {
        if ($op.OnTick) { try { & $op.OnTick $elapsed } catch { } }
        return
    }
    try { $op.Timer.Stop() } catch { }
    $script:HvgAsyncOps.Remove($Id)
    if ($timedOut) {
        $h.TimedOut = $true
        try { $h.Proc.Kill() } catch { }
        try { [void]$h.Proc.WaitForExit(3000) } catch { }
    }
    $res = Complete-HvgTool -Handle $h
    if ($op.OnDone) { try { & $op.OnDone $res } catch { Set-HvgStatusBar -Text ("HVGuard callback: " + $_.Exception.Message) } }
}
