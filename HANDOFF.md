# HANDOFF — defensive forensic analysis of the DenuvOwO bypass (ElAmigos / AC Shadows)

> Continuation point for another session or teammate. Status as of **2026-07-27**
> (earlier validation entries below are dated individually).
> Read `CLAUDE.md` (operating rules) first, then this handoff, before touching anything.

## 1. What this is (in one sentence)
**Blue team** project: understand, **detect**, **repair**, and **harden** against a Ring -1
hypervisor-based DRM bypass (DenuvOwO), using a sample that is a pirated ISO of **AC Shadows**
(ElAmigos, obtained through a third-party re-hosting mirror). **100% defensive. The sample is NEVER
executed.**

## 2. Unbreakable rules (summary of CLAUDE.md §1/§5/§8)
- **Never** execute/install/launch anything from the sample (not `setup.exe`, not the game, not
  `VBS.cmd`, not loading drivers).
- **Never** disable protections (VBS/HVCI/Secure Boot/DSE), compile/reconstruct the bypass, or
  distribute the crack.
- **Yes**, permitted and expected (§4): static analysis — hashing, PE/imports/exports,
  disassembly, `strings`, **extracting/reading** containers to analyze, diffing against clean
  upstreams.
- Whenever in doubt about (a) executing the sample, (b) disabling a protection, or (c) producing
  something that circumvents → **stop and ask**.

## 3. Environment
- **Analysis VM:** Ubuntu (VirtualBox) — this is where the agent runs. No Wine/emulators →
  Windows PEs do not execute here (zero risk).
- **Host:** Windows (where the ISO lives and where the tools would be tested/deployed). `sudo` on
  the VM prompts for a password; mount the ISO without sudo: `udisksctl loop-setup -r -f <iso>` +
  `udisksctl mount`.
- **Paths:** the repo/context directory (deliverables go here) and a separate, de facto read-only
  mount for the sample. Both are local to the analyst and intentionally not recorded here.
- **Tooling installed on the VM:** `pefile`, `capstone` (pip --user), `7z`, `objdump`, `strings`,
  `git`, `udisksctl`, `innoextract`, `binwalk`. Clean upstreams cloned into `~/work/upstreams`
  (SimpleSvm/HyperDbg/EfiGuard).

## 4. Key findings (details in `findings/analysis-summary.md`)
- Actual sample = an **AC _Shadows_** release. The context docs deliberately omit the title.
- Chain: UDF ISO → **Inno Setup 5.5.x** (SetupLdr signature stripped) →
  **FreeArc `elamigos-*.bin` payload ENCRYPTED with AES-256/CTR** (+ LOLZ/SREP codecs).
- **Phase A** done: `findings/hashes.csv`, `findings/inventory-report.md`.
- **Installer toolchain triaged and CLEAN** (`findings/toolchain-triage.md`): standard
  FreeArc/ISDone, no dropper. Partially answers "does the re-hosting mirror trojanize it?": not in the
  installer machinery.
- **DenuvOwO binaries NOT extracted:** the payload is **AES-256 encrypted**; the key is inside
  the installer (not statically extractable) and is only released by running `setup.exe`
  (forbidden). **Definitive cryptographic wall — do NOT retry with unverified scene binaries.**
  The *crack itself* is already dissected in the public reports in `doc 05`.

## 5. What's done / pending
**Done:**
- Static analysis of the sample as far as cleanly possible (Phase A + toolchain triage).
- **Complete defensive suite** in `defense/` (T0-T5 + T4 telemetry), with the broader coverage
  described under "Note on coverage" below.
- Findings deliverables in `findings/`.
- **HVGuard launcher (PowerShell + WPF GUI)** in `launcher/` + new
  **`defense/T7-target-scan.ps1`** engine: wraps the validated suite (launches it as a child
  process and reads its **JSON**, never the console), with 5 modules (Check/Repair/Harden/Game
  folder/Scanner), bilingual ES/EN, auto-elevation with degradation to **read-only** if UAC is
  cancelled. Engine calls run in the **background** (the window does not freeze; it shows
  elapsed seconds) and each tab has **vertical scrolling**. Packaged as **`dist/HVGuard.exe`** (a
  single self-contained file; C# stub + embedded ZIP, compiled offline with
  `tools/build-exe.ps1`). Implemented and validated (see below).

**User-selectable repair + critical finding in T5 (2026-07-26):**
- 🐛 **Real bug fixed in T5 (important).** `R1` was setting `RequirePlatformSecurityFeatures=1`
  **unconditionally**. That value **requires Secure Boot** for VBS to start; on a machine with
  Secure Boot OFF (dual-boot, or disabled for the crack) the requirement is **unmeetable** and
  VBS/HVCI end up `enabled, not running`: the repair reported "FIXED, reboot" and, after
  rebooting, **HVCI was still off**. In other words, T5 was leaving down *exactly* the
  countermeasure the bypass cannot get past. Measured on a real host:
  `RequiredSecurityProperties={1,2}` vs `AvailableSecurityProperties={1,3,4,5,6}` →
  **missing `2=SecureBoot`**.
  - **Fix:** `R1` now only requires Secure Boot **if the platform offers it**; new step
    **`R1b`** detects the unmeetable prerequisite and **removes** it (or lowers `3`→`1` if only
    DMA is missing) so that HVCI **runs**. Nothing is disabled: Secure Boot stays as it was, and
    enabling it is still guided in `R7`.
- ➕ **`R9`**: cleans up **residual IOC files** on disk (`%TEMP%`, Downloads, Desktop,
  `%ProgramData%`) via an allowlist of names, including empty `.tmp*` folders.
- ➕ **`R7` with real guidance**: `shutdown /r /fw /t 0` shortcut, what to do if the option is
  greyed out, a **dual-boot** warning, and a **BitLocker** warning (changing Secure Boot alters
  **PCR 7** → may prompt for the recovery key). And it explains **why it is impossible** to
  automate (read-only UEFI variable).
- ➕ **The user chooses what gets restored** (`T5 -Only` + GUI M2): one **checkbox per step**,
  checked by default, with a **"What is this?"** dropdown explaining
  **WHAT IT IS / WHY IT MATTERS / WHAT I'LL DO** in plain language (ES+EN, 11 steps),
  *reboot/immediate/key* badges, and *Check/Uncheck all*. `-Only` is a
  **fail-closed allowlist**; anything unchecked is reported as `SKIPPED`. Steps that are
  **not automatable** (R7, driver in use) are explained but **not** offered as a checkbox.
- ✅ Validated: **20/20** assertions of the `-Only` gate (against T5's actual code) and
  **26/26** of the selection GUI; self-test `rendered=True modules=5 initErrors=0` on
  **pwsh 7**, **WinPS 5.1**, and from the repackaged **`.exe`**. Hash of the real
  `SimpleSvm.sys` found in `%TEMP%`
  added to `findings/hashes.csv` (detection by **hash**, not just by name).

**Validation (2026-07-13):**
- ✅ **T1, T0, and T5 VALIDATED end-to-end** on real Windows (admin). Cycle tested and correct:
  healthy state → `PASS`/`CLEAN`; compromised state simulated by hand (HVCI off + `ManageVBS` +
  decoy file) → **T1 FAIL / T0 DETECTED**; **T5 `-Apply`** re-enabled HVCI and deleted
  `ManageVBS` (change confirmed OK; warns about reboot). All that remains is closing the loop
  with the reboot + `T1` → PASS.
- ✅ **T2 and T3 VALIDATED**: T2 `-Enforce` (idempotent; `COMPLIANT` with no reboot if VBS/HVCI
  are already running) + `-InstallMonitor` (`HVGuard-PostureMonitor` task;
  **7000 "posture compliant" AND 7001 "posture DRIFT" confirmed** in the Event Log +
  `posture-log.jsonl`). Note: those event-log messages were Spanish at the time of that validation;
  they are English now, so an old log entry and a new one read differently.
  T3 `-Audit` builds+deploys OK (merged blocklist). →
  **T0-T5 suite validated end-to-end on real Windows.**
- Bugs fixed during validation (all applied in `defense/`): (1) generic `New-Object` →
  `[...]::new()` in all 5 scripts ("Argument types do not match"); (2) BYOVD token `gdrv`
  bounded with `\b` (false positive on `EhStorTcgDrv`); (3) **T3**'s blocklist merge is now
  **non-fatal** (local copy + temp output; used to abort on "Access denied"); (4) **T2** no
  longer requires a reboot if VBS/HVCI are already running.
- **T3 1.1.0 (2026-09-28):** (1) no longer enables `Enabled:UMCI`. With UMCI in audit mode,
  PowerShell 7 reported `ConstrainedLanguage` machine-wide (and `-Enforce` would have blocked every
  non-Microsoft app); the policy is now kernel-only. (2) `Set-CIPolicyIdInfo -PolicyId` only set a
  text label, so the policy kept the Microsoft template GUID `{E0ABDA1F-…}` and `-Remove` removed
  nothing while reporting success. The own GUID is now written into `<PolicyID>`/`<BasePolicyID>`;
  `-Audit` migrates (removes) the old template-GUID policy, `-Remove` finds policies by name, and
  CiTool results are checked (`--json`). (3) The version is bumped from the deployed one instead of
  a fixed `1.0.0.0`. `-Status` warns if a deployed policy still has UMCI.

**Pending / open:**
- **HVGuard launcher (GUI):** **IMPLEMENTED** in `launcher/` (see `launcher/README.md` and
  `launcher/TEST-RUNBOOK-WINDOWS.md`). Reference plan in `docs/06-hvguard-design.md` (§13 =
  implementation status). **Validated (2026-07-13, real Windows, read-only):** engine↔GUI
  (`Invoke-HvgTool` → JSON) on pwsh 7 **and** WinPS 5.1; `Shell.xaml` parses (21 names);
  `-SelfTest` renders and degrades to read-only, bilingual; **5 modules** init with no error;
  **T7** detects hash-IOC + name-IOC (`KNOWN-THREAT`), unsigned `.sys` (`SUSPECT`), and does
  **not** false-positive on a signed PE (`CLEAN`). **Pending:** full
  *compromised→repair→green* cycle with real `-Apply`/`T2 -Enforce`/`T3 -Audit` (disposable VM
  with snapshot only — steps in the runbook §3), and **Authenticode signature** for
  `dist/HVGuard.exe` for distribution (packaging itself is already done).
- **T4 (Sysmon/Sigma/YARA):** deploy/validate — this is detection content + deployment, not
  script logic.
- **T3 `-Enforce`:** make the jump to real blocking **only** after reviewing the 3076 events
  from `-Audit` mode (boot risk).
- **Operationalize:** deploy the already-validated suite on real endpoints.
- Extraction of the bypass binaries: **closed** (crypto). If first-hand RE is needed, use a
  sample from a **legitimate feed** (VT Intelligence/MalwareBazaar), not the ISO.

## 6. Repo map
- `defense/` — tools (see `defense/README.md` for the table and deployment order):
  - `T1-posture-check.ps1` (posture PASS/FAIL) · `T0-hv-detector.ps1` (T0/T6 detector) ·
    `T2-hvci-enforce-monitor.ps1` · `T3-wdac-block-unsigned-drivers.ps1` ·
    `T5-remediation.ps1` · `telemetry/` (Sysmon+Sigma+YARA).
- `tools/` — `phase-a-inventory.py`, `pe-triage.py` (one-off Linux forensics), `build-exe.ps1` +
  `exe/` (packaging), `check-plain-language.ps1` + `plain-language-vocabulary.psd1` (the gate that
  keeps user-facing text readable).
- `findings/` — `hashes.csv`, `inventory-report.md`, `toolchain-triage.md`,
  `analysis-summary.md`.
- `01`-`05` (+ `README.md`) — original context/RAG (not rewritten; corrections in
  `findings/analysis-summary.md`).
- Note on coverage: an earlier, separate mitigation draft produced during this same project
  suggested several additional checks, which are now **implemented independently** in the suite
  (`nointegritychecks`, the vulnerable-driver blocklist, Smart App Control, the BYOVD driver list,
  and driver quarantine). All of them are documented Windows features. Its Secure Boot verdict was
  **deliberately not** reproduced: here Secure Boot is context, not a decisive failure.

## 7. How to test without touching the crack (E2E validation)
- **Read-only, safe on any Windows:** `T1` and `T0` (read real state; on a healthy host →
  PASS/CLEAN).
- **"Compromised" state for T5/T2/T3:** on a **disposable Windows** machine, reproduce the
  *footprint* by hand (`bcdedit /set testsigning on`, create `HKLM\SOFTWARE\ManageVBS`, turn off
  Memory integrity) → `T0` detects → `T5 -Apply` reverts → `T1` verifies. **Never** run the
  crack to "create" the state.

## 8. Scope decisions (log)
- Crack extraction: first ruled out on legitimacy grounds; then reframed as static analysis
  (permitted by §4); finally **blocked by AES-256 encryption** (not by policy or caution).
- **Secure Boot OFF ≠ compromise** (common in multi-boot setups): downgraded to context/WARN in
  T0/T1. The decisive countermeasure is **HVCI**.
