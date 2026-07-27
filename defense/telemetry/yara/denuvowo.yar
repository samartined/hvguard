/*
   T4 - YARA rules (over FILE, not live memory) for the DenuvOwO hypervisor bypass.
   Defensive. The strings come from PUBLIC INTEL (doc 02 §3.1) and from the upstream OSS projects
   (SimpleSvm by Satoshi Tanda, HyperDbg by Sina Karvandi). They do NOT derive from the crack binary.
   Narrow further once a sample is available through a legitimate channel (VT Intelligence / MalwareBazaar).
   Usage:  yara -r denuvowo.yar <path>
*/

rule DenuvOwO_SimpleSvm_AMD_Hypervisor
{
    meta:
        description = "AMD SVM hypervisor driver of the SimpleSvm type (basis for the bypass's SimpleSvm.sys)"
        reference   = "docs/02-iocs-and-load-chain.md §3.1; OSS SimpleSvm (Satoshi Tanda)"
        note        = "PUBLIC lifecycle strings from the upstream project. Strong signal but not infallible."
        tlp         = "CLEAR"
    strings:
        $a = "Attempting to virtualize the processor" ascii wide
        $b = "The processor has been virtualized" ascii wide
        $c = "SVM is not fully supported on this processor" ascii wide
        $d = "de-virtualized" ascii wide nocase
        $e = "SimpleSvm" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($a,$b,$c,$d,$e)
}

rule DenuvOwO_HyperDbg_VMM
{
    meta:
        description = "VMM core based on HyperDbg (basis for the bypass's hyperhv.dll)"
        reference   = "docs/01-technical-dossier.md §5.1; OSS HyperDbg (Sina Karvandi)"
        note        = "Public HyperDbg markers. Correlate before concluding."
    strings:
        $h1 = "hyperdbg" ascii wide nocase
        $h2 = "hyperhv"  ascii wide nocase
        $h3 = "VmxVmcall" ascii wide
        $h4 = "EptHook"   ascii wide nocase
        $h5 = "hyperevade" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule DenuvOwO_Component_Or_Tracking_Names
{
    meta:
        description = "Component/artifact names from the DenuvOwO package (weak signal; use as a pivot)"
        note        = "Match on an embedded name inside a PE; correlate, do not conclude from this alone."
        caveat      = "Gated to PE files and excludes this project's own tooling on purpose - see below."
        tlp         = "CLEAR"
    strings:
        $n1 = "hyperkd"              ascii wide nocase
        $n2 = "hyperevade"           ascii wide nocase
        $n3 = "DenuvOwO"             ascii wide nocase
        $n4 = "hypervisor-launcher"  ascii wide nocase
        $n5 = "ManageVBS"            ascii wide nocase
        $n6 = "DenuoOwO_SRC"         ascii wide nocase
        // Self-exclusion. Every $n string above also appears in THIS project's own text: in the docs,
        // in findings/hashes.csv, and inside dist/HVGuard.exe, which embeds a ZIP of the scripts and
        // that CSV. Without the PE gate and this exclusion, scanning a machine that has HVGuard on it
        // flags HVGuard itself - a defensive tool reporting itself as the threat it defends against.
        $self = "HVGuard" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 64MB
        and not $self
        and any of ($n*)
}
