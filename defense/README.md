# Defensive suite — anti hypervisor-based DRM bypass (DenuvOwO family)

*Blue team* tools to **prevent, detect, repair and watch** the Ring -1 hypervisor-based bypass
technique. **100% defensive.** They do not reproduce, extract or package the crack; they are built on
**platform state** (VBS/HVCI/Secure Boot/testsigning/DeviceGuard) and **public IOCs** (doc 02 and the
RE reports in doc 05).

## Thesis (why this is enough)
The technique **depends** on leaving the system insecure: **HVCI + Secure Boot turned off** and
**loading an unsigned driver** (on an **AMD/SVM** host, `SimpleSvm.sys`). HVCI (VTL1) cannot be
bypassed. So the correct defense is not complex: **secure and watch those controls, detect state
changes, and be able to revert them.**

## Tools

| ID | File | Function | Touches system |
|----|---------|---------|--------------|
| **T1** | `T1-posture-check.ps1` | **Posture** verifier PASS/FAIL (testsigning, **nointegritychecks**, VBS, HVCI + Secure Boot as context + ManageVBS IOC + informational blocklist/SAC) | no (read-only) |
| **T0/T6** | `T0-hv-detector.ps1` | **Detector** (live / residual `-PostExecution`): unexplained hypervisor, defense state, file/registry/driver IOCs (bypass **+ known BYOVD drivers**) | no (read-only) |
| **T5** | `T5-remediation.ps1` | **Remediation**: re-enables VBS/HVCI, testsigning/**nointegritychecks** off, **Vulnerable Driver Blocklist** on, cleans up `ManageVBS`, **quarantines** (or deletes) the residual driver, Secure Boot guidance | yes (**dry-run by default**) |
| **T2** | `T2-hvci-enforce-monitor.ps1` | **Enforces** HVCI/VBS + drift **monitor** (scheduled task → Event Log) | yes (`-Enforce`/`-InstallMonitor`) |
| **T3** | `T3-wdac-block-unsigned-drivers.ps1` | **WDAC** policy that blocks unsigned drivers | yes (**audit by default**) |
| **T4** | `telemetry/` | **Sysmon** + **Sigma** rules + **YARA** (file-based) | no (detection) |

**Expanded coverage (2026-07-13 unification):** an earlier, separate mitigation draft produced
during this project suggested further checks, implemented independently here: `nointegritychecks`
(another way to break DSE), Microsoft's **Vulnerable Driver Blocklist** (anti-BYOVD), **Smart App
Control** (informational), a list of known **BYOVD vulnerable drivers**, and driver **quarantine**
(`sc config start=disabled`) as a reversible alternative to deletion. Its false **Secure Boot** "RISK"
was not carried over: here Secure Boot is **context** (commonly OFF in multi-boot setups), not a
decisive failure — the decisive control is **HVCI**.

## Recommended deployment order
1. **T1** — posture baseline (also serves as the final verification of everything else).
2. **T4** — telemetry (Sysmon + Sigma + YARA): immediate visibility, changes nothing.
3. **T2** — `-Enforce` (enforces HVCI/VBS) + `-InstallMonitor` (alerts if something re-opens them).
4. **T3** — WDAC in `-Audit`; review CodeIntegrity 3076/3077; then `-Enforce`.
5. **T5** — only if a machine has already been compromised: `-Apply` to revert the weakened settings, restart, re-validate with T1.
6. **T0/T6** — on-demand detection / incident response (`-PostExecution` for "it already ran").

## Quality criteria (all scripts)
- **Idempotent**, with **logging** and **exit codes** (0 healthy/OK · 1 pending/restart · 2 error).
- **Dry-run by default** for anything that modifies state (T2/T3/T5). They **never disable** a protection.
- **Human-readable + JSON** output (`-AsJson`/`-JsonPath`) for SIEM integration.
- Every finding/action **traced to evidence** (observed vs. expected value).

## Usage safety
- These scripts are for Windows; **validate and test them on a disposable Windows VM with snapshots**
  before using them on a real machine (here, on the Linux analysis VM, there is no PowerShell).
- **WDAC (T3) can prevent booting** if misconfigured: that is why it ships in audit mode by default,
  with a rollback path (`-Remove`). Adjust the signers for your organization.
- The direction is **always toward more security**. No tool disables VBS/HVCI/Secure Boot/DSE or loads
  drivers.

## Scope
**Exclusively defensive** project. The bypass binaries and their source code are neither extracted nor
distributed. Analysis of the sample was limited to inventory/classification of the distribution media
(`../findings/`); the IOCs used here come from public sources (doc 02/05).
