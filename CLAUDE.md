# CLAUDE.md — Agent operating rules

This project is a **defensive forensic analysis** of a hypervisor-based DRM bypass. Before any
action, internalize these rules. They apply in **all** sessions.

## 1. Golden rule: never execute the sample

- **NEVER execute, load, install, or launch any binary from `sample/`** (`.exe`, `.sys`, `.dll`,
  `.cmd`, `.bat`, installers, or the game itself). Not "just to test", not in the background, not
  via another process.
- **NEVER** execute the sample's `VBS.cmd` or any script that disables VBS/HVCI/DSE/Secure Boot,
  enables `testsigning`, or loads an unsigned driver.
- If a task appears to require executing something from the sample to move forward,
  **stop and ask**. There is almost always an equivalent static approach.

## 2. Why the environment is safe (and when it stops being so)

- **Claude Code is not a sandbox.** It acts on the filesystem where it is launched. **Isolation**
  is provided by the **environment**, not the tool.
- The analysis environment is **Linux** (a dedicated VM or WSL2). The sample binaries are
  **Windows** binaries and **cannot execute on Linux** — there is no loader to start them. That is
  why the static analysis here has **zero execution risk**.
- **Do not** try to install Wine, an emulator, a compatibility layer, or nested virtualization to
  "run" a sample binary. That would break the safety guarantee. If you detect Wine or something
  similar installed, **warn before working**.
- Testing the **defensive tools** we build (which are *ours*, not the crack) is done on a
  **disposable Windows VM with snapshots**, in the final phase, never against the sample.

## 3. The sample is read-only

- Treat `sample/` as **read-only** (ideally `chmod -R a-w sample/`). Do not modify it, move it,
  destructively decompress it "in place", or rename it.
- Work on **copies** or on tool outputs (dumps, disassemblies, `strings`), never altering the
  original — preserve the chain of custody.
- Record the **SHA-256** of every artifact before touching it.

## 4. What IS permitted and is the expected work

**Static** analysis and defensive construction:

- Hashing (SHA-256), file inventory, entropy calculation.
- Parsing **PE** headers and sections (`pefile`), import/export table, Authenticode signatures.
- Disassembly (`capstone`, `radare2`, `objdump`), triage with Ghidra if available.
- `strings`, parsing `.inf`, reading `.cmd`/`.nfo`/`.txt` **as text** (reading ≠ executing).
- Reading the **source code** included in the package (`DenuoOwO_SRC.7z`) and
  **diffing against the clean upstreams** (SimpleSvm, HyperDbg, EfiGuard) to separate *stock*
  from *custom*.
- Extracting **IOCs** (driver/service/file names, hashes, registry keys, boot chains) and
  drafting detection rules (Sigma, YARA over files, not live memory).
- Designing and implementing the **defensive tools** (see `docs/04-defensive-tools-spec.md`): posture checker, HVCI
  monitor/enforcement, WDAC policy, telemetry (Sysmon/CodeIntegrity), remediation, detector.

## 5. Content limits (do not cross)

- **Do not** reconstruct, assemble, compile, or "fix" the bypass artifact or any part that would
  make it functional as a Denuvo circumvention. Understanding and explaining the mechanics: yes.
  Producing the tool that circumvents: no.
- **Do not** write a bootkit or code that disables Secure Boot / PatchGuard / DSE / HVCI.
  Remediation goes **in the opposite direction**: re-enabling those protections.
- **Do not** include in the repo any crack download links, mirrors, magnets, or the bypass
  source package. Reference by name/hash for detection purposes.
- Study material is cited **from clean sources** (Intel SDM, AMD APM, reference open-source
  projects), never the integrated tool.

## 6. Data and credential hygiene

- This analysis may run on a machine with access to sensitive infrastructure. **Do not**
  exfiltrate anything, **do not** make network calls to/from the sample, **do not** upload sample
  artifacts to external services.
- If you generate IOCs or reports, keep them in `findings/`. Do not mix secrets from the user's
  environment into the repo's documents.

## 7. Default workflow

1. Before generating specific code, **confirm three variables**: target host architecture
   (**Intel/VMX** vs **AMD/SVM**), tool language (**PowerShell** vs compiled), and whether the
   package is **extracted** with a **VM/WSL** ready.
2. Start with what **does not touch the sample** and delivers immediate value:
   **posture checker** and **detector** (`docs/04-defensive-tools-spec.md`).
3. For sample analysis: inventory + hashes → PE/imports → identify loader/VMM/evasion layer →
   read `SRC` and **diff** against upstreams → extract IOCs → document in `findings/`.
4. Work in an **incremental and auditable** way: every script commented, every finding traced to
   its evidence (hash, offset, string, or source line).

## 8. When in doubt

If an action could (a) execute something from the sample, (b) disable a system protection, or
(c) produce something that functions as a circumvention — **stop and ask**. Caution is cheap;
undoing a Ring -1 code execution is not.
