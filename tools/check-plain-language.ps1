#Requires -Version 5.1
<#
.SYNOPSIS
    Plain-language gate for HVGuard's user-facing text.

.DESCRIPTION
    HVGuard is aimed at non-technical people in a harm-reduction context. "Is this understandable?"
    is normally a matter of opinion, which means it drifts. This script turns it into a measurable,
    repeatable check so it can be enforced like any other test.

    It extracts the strings the user actually reads - the $es/$en tables in launcher/lib/Modules/M*.ps1
    and launcher/lib/i18n/*.psd1 - classifies each one by disclosure layer, and applies a budget:

        Layer 1 (labels, titles, status hints, badges)
            The lay reading path. Budget: ZERO jargon terms and ZERO bare acronyms.
        Layer 2 (the "What is this?" explanations, intros, banners)
            Still the lay path, but allowed to introduce vocabulary. Budget: jargon density under
            -MaxDensity, and every acronym must be glossed - i.e. written as "Plain name (ACRONYM)"
            at least once in that same string, or listed in GLOSSARY.md.
        Layer 3 (keys ending in 'Tech', or listed in $script:Layer3Keys)
            The technical detail drawer, for curious or expert readers. Not budgeted - this is where
            registry paths, security properties, event IDs and PCR numbers belong.

    Jargon and acronym vocabularies live in tools/plain-language-vocabulary.psd1 so the rules are
    data, not code, and can be reviewed in a diff.

.PARAMETER Lang
    Which language table to check: en, es, or both (default).

.PARAMETER MaxDensity
    Maximum percentage of words in a Layer-2 string that may be jargon. Default 4.

.PARAMETER MaxWordsPerSentence
    Maximum average words per sentence for Layer 1 and 2. Default 22.

.PARAMETER Detail
    Print every offending string in full, not just a summary.

.OUTPUTS
    Exit 0 = within budget. Exit 1 = violations found. Exit 2 = could not run.

.NOTES
    Read-only. Never modifies the repo. Intended for CI and for a pre-release check.
#>
[CmdletBinding()]
param(
    [ValidateSet('en', 'es', 'both')][string]$Lang = 'both',
    [double]$MaxDensity = 4.0,
    [int]$MaxWordsPerSentence = 22,
    [switch]$Detail
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$VocabPath = Join-Path $PSScriptRoot 'plain-language-vocabulary.psd1'
if (-not (Test-Path -LiteralPath $VocabPath)) {
    Write-Error "Vocabulary file not found: $VocabPath"
    exit 2
}
$Vocab = Import-PowerShellDataFile -LiteralPath $VocabPath

# Keys that are the technical drawer (Layer 3) and therefore unbudgeted.
$script:Layer3Keys = @($Vocab.Layer3Keys)
# Keys that are short labels/titles/badges (Layer 1) - strictest budget.
$script:Layer1Keys = @($Vocab.Layer1Keys)

$jargon = @($Vocab.Jargon)
# Only real acronyms are policed. This UI shouts ordinary words for emphasis (NEVER, BEFORE, OJO...),
# so "any run of capitals" would be far too noisy to be useful.
$knownAcronyms = @($Vocab.KnownAcronyms)

$jargonPat = if ($jargon.Count) {
    '(?i)(?<![\w-])(' + (($jargon | Sort-Object { $_.Length } -Descending |
        ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![\w-])'
} else { $null }

# =====================================================================================================
#  Extraction
# =====================================================================================================
function Get-HvgUserStrings {
    param([string]$Language)
    $out = [System.Collections.Generic.List[object]]::new()
    $tableNames = if ($Language -eq 'en') { 'en|map_en' } else { 'es|map_es' }

    foreach ($f in (Get-ChildItem (Join-Path $RepoRoot 'launcher/lib/Modules') -Filter 'M*.ps1' -File)) {
        $txt = Get-Content -LiteralPath $f.FullName -Raw
        foreach ($m in [regex]::Matches($txt, "(?s)\`$($tableNames)\s*=\s*@\{(.*?)\n(\s*)\}")) {
            $table = $m.Groups[1].Value          # 'en' | 'map_en' | 'es' | 'map_es'
            foreach ($km in [regex]::Matches($m.Groups[2].Value,
                    "(?m)^\s*([A-Za-z0-9_]+)\s*=\s*(['`"])(.*?)\2\s*$")) {
                $out.Add([pscustomobject]@{
                    Source = $f.Name; Table = $table
                    Key = $km.Groups[1].Value; Text = $km.Groups[3].Value
                })
            }
        }
    }
    $psd = Join-Path $RepoRoot "launcher/lib/i18n/$Language.psd1"
    if (Test-Path -LiteralPath $psd) {
        foreach ($km in [regex]::Matches((Get-Content -LiteralPath $psd -Raw),
                "(?m)^\s*([A-Za-z0-9_]+)\s*=\s*'(.*?)'\s*$")) {
            $out.Add([pscustomobject]@{
                Source = "$Language.psd1"; Table = 'psd1'
                Key = $km.Groups[1].Value; Text = $km.Groups[2].Value
            })
        }
    }
    return $out
}

function Get-HvgLayer {
    <# Which disclosure layer a string belongs to. See the script header for the budget per layer. #>
    param([string]$Key, [string]$Table)
    if ($script:Layer3Keys -contains $Key -or $Key -match 'Tech$') { return 3 }
    # The map_* tables hold the short, human-readable step TITLES shown next to each checkbox, so they
    # are Layer 1 even though their keys (R1, R2, ...) also name the long Layer-2 explanations.
    if ($Table -like 'map_*') { return 1 }
    if ($script:Layer1Keys -contains $Key) { return 1 }
    return 2
}

# =====================================================================================================
#  Checking
# =====================================================================================================
function Test-HvgStrings {
    param([string]$Language)

    $strings = Get-HvgUserStrings -Language $Language
    if ($strings.Count -eq 0) {
        Write-Warning "No strings extracted for '$Language'."
        return [pscustomobject]@{ Language = $Language; Checked = 0; Violations = @() }
    }

    $violations = [System.Collections.Generic.List[object]]::new()
    $checked = 0

    foreach ($s in $strings) {
        $layer = Get-HvgLayer -Key $s.Key -Table $s.Table
        if ($layer -eq 3) { continue }
        # Normalize: drop escapes and format placeholders so they do not skew word counts.
        $t = $s.Text -replace '`n', ' ' -replace '`r', ' ' -replace '\{\d+\}', 'X'
        if ($t.Trim().Length -lt 12) { continue }     # bare labels: nothing to read
        $checked++

        $words = @($t -split '\s+' | Where-Object { $_ -match '\w' })
        if ($words.Count -eq 0) { continue }
        $sentences = @($t -split '(?<=[.!?:])\s+' | Where-Object { $_.Trim() })
        $wps = [math]::Round($words.Count / [math]::Max(1, $sentences.Count), 1)

        # NOTE: the @() must wrap the whole `if`. Writing `$x = if (..) { @() }` yields $null, not an
        # empty array, because PowerShell unrolls the statement's output.
        $jHits = @(if ($jargonPat) { [regex]::Matches($t, $jargonPat) | ForEach-Object { $_.Value } })
        $density = [math]::Round(100 * $jHits.Count / $words.Count, 1)

        # Which known acronyms does this string use, and are they introduced properly?
        $acr = @($knownAcronyms | Where-Object {
            [regex]::IsMatch($t, '(?<![\w-])' + [regex]::Escape($_) + '(?![\w-])')
        })
        # Glossed = written somewhere in the same string as "Plain name (ACRONYM)".
        $ungl = @($acr | Where-Object {
            -not ([regex]::IsMatch($t, '\(\s*' + [regex]::Escape($_) + '\s*\)'))
        })

        $issues = @()
        if ($layer -eq 1) {
            if ($jHits.Count -gt 0) { $issues += "L1 must have no jargon: $(($jHits | Select-Object -Unique) -join ', ')" }
            if ($acr.Count -gt 0)   { $issues += "L1 must have no acronyms: $($acr -join ', ')" }
        } else {
            if ($density -gt $MaxDensity) {
                $issues += ("jargon density {0}% > {1}% [{2}]" -f $density, $MaxDensity, (($jHits | Select-Object -Unique) -join ', '))
            }
            if ($ungl.Count -gt 0) { $issues += "unglossed acronym(s): $($ungl -join ', ')" }
        }
        if ($wps -gt $MaxWordsPerSentence) { $issues += ("{0} words/sentence > {1}" -f $wps, $MaxWordsPerSentence) }

        if ($issues.Count -gt 0) {
            $violations.Add([pscustomobject]@{
                Language = $Language; Source = $s.Source; Key = $s.Key; Layer = $layer
                Density = $density; WordsPerSentence = $wps
                Issues = ($issues -join ' | '); Text = $s.Text
            })
        }
    }
    return [pscustomobject]@{ Language = $Language; Checked = $checked; Violations = @($violations) }
}

# =====================================================================================================
#  Run
# =====================================================================================================
$langs = if ($Lang -eq 'both') { @('en', 'es') } else { @($Lang) }
$allViolations = @()
$totalChecked = 0

foreach ($l in $langs) {
    $r = Test-HvgStrings -Language $l
    $totalChecked += $r.Checked
    $allViolations += $r.Violations
    "{0}: {1} strings checked, {2} violation(s)" -f $l, $r.Checked, $r.Violations.Count
}

''
if ($allViolations.Count -eq 0) {
    "PLAIN-LANGUAGE GATE: PASS  ($totalChecked strings within budget)"
    exit 0
}

$allViolations | Group-Object Language | ForEach-Object {
    ''
    "=== $($_.Name.ToUpper()) ==="
    $_.Group | Sort-Object Layer, Source, Key |
        Select-Object Source, Key, Layer, Issues | Format-Table -AutoSize -Wrap
}

if ($Detail) {
    foreach ($v in ($allViolations | Sort-Object Language, Layer, Source, Key)) {
        ''
        "[{0} / {1} / {2}] L{3}" -f $v.Language, $v.Source, $v.Key, $v.Layer
        "  $($v.Issues)"
        "  > $($v.Text)"
    }
}

''
"PLAIN-LANGUAGE GATE: FAIL  ($($allViolations.Count) violation(s) across $totalChecked strings)"
exit 1
