# =====================================================================================================
#  Vocabulary rules for tools/check-plain-language.ps1
#
#  These are DATA, not code, so that changes to what counts as "jargon" show up in a reviewable diff.
#
#  The premise: HVGuard is used by people who are worried, not curious. Anything they must look up
#  elsewhere before they can act is a defect. Terms below are the ones a general audience does not
#  know without being taught, so they are either replaced with a plain phrase or introduced as
#  "Plain name (ACRONYM)" and recorded in the glossary.
# =====================================================================================================
@{

    # -------------------------------------------------------------------------------------------------
    #  Terms a non-technical reader will not know. Layer 1 may contain none of these; Layer 2 is
    #  budgeted by density (see -MaxDensity).
    # -------------------------------------------------------------------------------------------------
    Jargon = @(
        # virtualization / kernel concepts
        'hypervisor', 'hipervisor', 'virtualization', 'virtualizacion', 'kernel', 'nucleo',
        'ring -1', 'ring 0', 'VTL1', 'guest', 'host',
        # Windows security features referred to by their internal names
        'VBS', 'HVCI', 'DSE', 'WDAC', 'PatchGuard', 'BYOVD', 'Code Integrity',
        'testsigning', 'test-signing', 'test signing', 'nointegritychecks',
        'hypervisorlaunchtype', 'RequirePlatformSecurityFeatures', 'VulnerableDriverBlocklistEnable',
        # boot / firmware
        'UEFI', 'BIOS', 'firmware', 'bcdedit', 'BCD', 'bootkit', 'boot chain', 'PCR', 'PCR 7',
        'Platform Key', 'SetupMode', 'DBX',
        # forensics / detection vocabulary
        'IOC', 'IOCs', 'YARA', 'Sigma', 'Sysmon', 'entropy', 'entropia', 'Authenticode',
        'PE header', 'hash', 'SHA-256', 'heuristic', 'heuristica', 'telemetry', 'telemetria',
        'posture', 'postura', 'baseline', 'delta', 'remediation', 'remediacion', 'dry-run', 'dry run',
        'allowlist', 'blocklist', 'lista blanca', 'quarantine', 'cuarentena',
        # plumbing that leaked into user text
        'registry', 'registro', 'WMI', 'JSON', 'JSONL', 'Event Viewer', 'Visor de eventos',
        'scheduled task', 'DMA', 'STA', 'UAC', 'ProgramData', 'LOCALAPPDATA',
        # project-internal names
        'DenuvOwO', 'SimpleSvm', 'ManageVBS', 'hyperkd', 'hyperhv', 'hyperevade',
        'HVGuard-PostureMonitor', 'HVGuard-BlockUnsignedDrivers'
    )

    # -------------------------------------------------------------------------------------------------
    #  Acronyms the checker actually polices.
    #
    #  Deliberately an ALLOWLIST of real acronyms rather than "any run of capitals": this UI shouts
    #  ordinary words for emphasis on purpose (NEVER, BEFORE, WOULD, OJO, NUNCA...) and those are not
    #  acronyms. Listing the real ones keeps the check precise instead of noisy.
    #
    #  Rule enforced: in Layer 2 each of these must be introduced at least once in the same string as
    #  "Plain language name (ACRONYM)". In Layer 1 they may not appear at all.
    # -------------------------------------------------------------------------------------------------
    KnownAcronyms = @(
        'VBS', 'HVCI', 'DSE', 'WDAC', 'BYOVD', 'VTL1', 'KPP',
        'UEFI', 'BIOS', 'BCD', 'PCR', 'DBX', 'CSM', 'TPM', 'DMA', 'SMM', 'MBEC',
        'IOC', 'IOCS', 'PE', 'YARA', 'SHA', 'VT', 'API',
        'WMI', 'JSON', 'JSONL', 'CSV', 'XML', 'STA', 'MTA', 'UAC', 'GUI', 'CLI', 'PS',
        'SVM', 'VMX', 'AMD', 'VM', 'HV', 'KB', 'MB', 'GB'
    )

    # -------------------------------------------------------------------------------------------------
    #  Layer 1: short labels, titles, badges, status hints. Strictest budget - no jargon, no acronyms.
    # -------------------------------------------------------------------------------------------------
    Layer1Keys = @(
        'title', 'btn', 'btnScan', 'btnApply', 'btnAnalyze', 'btnBefore', 'btnAfter', 'btnHarden',
        'btnAudit', 'browse', 'pathLbl', 'selAll', 'selNone', 'whatIs', 'stepPrefix', 'curState',
        'bReboot', 'bNow', 'bKey', 'chkWatch', 'chkOnline', 'modePre', 'modePost',
        'watchOn', 'watchOff', 'done', 'healthy', 'cleanH', 'suspectH', 'knownH', 'errH',
        'deltaOkH', 'deltaBadH', 'analyzeH', 'watchH', 'confirmTitle', 'manualHdr'
    )

    # -------------------------------------------------------------------------------------------------
    #  Layer 3: the technical drawer. Unbudgeted - registry paths, event IDs, security properties and
    #  PCR numbers belong here, never in Layer 1 or 2. Keys ending in 'Tech' are Layer 3 automatically.
    # -------------------------------------------------------------------------------------------------
    Layer3Keys = @(
        'watcher', 'auditNote', 'deltaLimit', 'never', 'blind'
    )
}
