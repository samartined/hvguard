# HVGuard - "chrome" strings (header, tabs, status light). EN.
# Module-specific strings live inside each module. Loaded with explicit UTF-8 reading
# (Import-HvgStrings) so accented characters survive on Windows PowerShell 5.1 and PowerShell 7.
@{
    AppTitle           = 'HVGuard'
    AppSubtitle        = 'Protect your PC from what the crack turns off'
    LangLabel          = 'Language'
    Ready              = 'Ready.'
    DetailsHeader      = 'View details'

    Tabs = @{
        Status  = 'Check'
        Repair  = 'Repair'
        Harden  = 'Harden'
        Folder  = 'Game folder'
        Scanner = 'Scanner'
    }

    Status = @{
        NotChecked  = 'NOT CHECKED'
        Working     = 'CHECKING…'
        Protected   = 'PROTECTED'
        AtRisk      = 'AT RISK'
        Compromised = 'COMPROMISED'
        Unknown     = 'INCONCLUSIVE'
    }

    StatusHintDefault  = 'Click "Check" to review your PC''s state.'
    ReadOnlyBanner     = 'Read-only mode: HVGuard is running without administrator rights. You can Check and Analyze, but to Repair or Harden restart it as administrator.'
    ReadOnlyTag        = 'read-only'
    AdminTag           = 'administrator'
    NeverFalseSecurity = 'Green means "no known threats found", never "it is safe".'
    CopyAll            = 'Copy all'
    Copied             = 'Copied to clipboard.'
}
