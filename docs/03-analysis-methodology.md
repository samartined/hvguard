# 03 — Safe static analysis methodology

How to analyze the sample **without executing it** and with **zero** risk to the machine. This
document defines the environment and the runbook. Full operating rules in `CLAUDE.md`.

---

## 1. Environment security model

**Principle:** isolation is not provided by Claude Code (which acts on the filesystem where it is
launched); it is provided by the **environment**.

**Zero execution-risk move:** analyze the **Windows** binaries (`.sys`/`.exe`/`.dll`) **from Linux**
(dedicated VM or **WSL2**). On Linux there **is no loader** that will boot a Windows PE, so all
static analysis (hashing, PE parsing, disassembly, `strings`, code reading) **executes nothing by
definition**. This is exactly the approach used by the reference audits (radare2/objdump/readelf/
strings on WSL Ubuntu, **without executing** the binaries). *[audit]*

**Environment rules:**
- Copy the **extracted** sample to `sample/` inside the VM/WSL and make it **read-only**:
  `chmod -R a-w sample/`.
- **Do not** install Wine, emulators, or compatibility layers. **Do not** enable nested
  virtualization to "run" anything from the sample. That would break the guarantee.
- **No network** to/from the sample. The analysis does not need internet access (except to clone the
  **clean upstreams** from GitHub, which is done separately).
- To **test the defensive tools** (ours, not the crack): **disposable Windows VM with snapshots**,
  final phase.

---

## 2. Toolchain

| Purpose | Tools |
|---|---|
| Hashing / inventory | `sha256sum`, `find`, entropy calculation |
| PE headers / imports / signatures | `pefile` (Python), `readelf`/`objdump` for format |
| Disassembly / decompilation | `capstone` (Python), `radare2`, Ghidra (if available) |
| Strings / resources | `strings`, `binwalk` (container triage) |
| Reading scripts/config | text editor (`.cmd`, `.inf`, `.nfo`, `.ini`, `.txt`) |
| Diff against upstream | `git`, `diff`, per-function/section hash comparison |
| Detection rules | YARA (file-based), Sigma (log-based) |

Claude Code writes and runs the scripts (`pefile`+`capstone`), interprets the output, and drafts the
report in `findings/`.

---

## 3. Runbook (phases)

### Phase A — Inventory and chain of custody
1. Recursively list `sample/`; record the size and **SHA-256** of every file →
   `findings/hashes.csv`.
2. Classify by type (executable PE, `.sys` driver, DLL, script, doc, archive).
3. Per-file entropy (detect packing/encryption in sections).

### Phase B — PE triage (for each `.exe`/`.sys`/`.dll`)
1. Headers: `Machine`, `Subsystem` (`.sys` files are usually **Native**, Subsystem=1),
   `Characteristics`, timestamps.
2. **Authenticode signature:** presence/validity (drivers are expected to be **unsigned** →
   consistent with the need for DSE off).
3. **Imports:** flag APIs of interest:
   - Driver/kernel: `ZwLoadDriver`, `NtLoadDriver`, services (`CreateService`/`OpenSCManager`).
   - Registry: `RegSetValueEx`/`RegCreateKeyEx` (correlate with `ManageVBS`).
   - Virtualization/CPU: use of VMX/SVM intrinsics, `__cpuid`, MSR access.
   - **Network / injection / exfiltration**: `WinInet`/`WinHTTP`/sockets, `WriteProcessMemory`,
     `CreateRemoteThread`. **Their absence** is what the audits report as "not malware". *[audit]*
4. **Exports** (DLLs): the surface of the VMM (`hyperhv.dll`) and of the evasion layer
   (`hyperevade.dll`).

### Phase C — Identifying the loader / VMM / evasion
Map each binary to its role (see `docs/02` §1) based on imports/exports/strings:
- `hypervisor-launcher.exe` → orchestration + game launch.
- `SimpleSvm.sys` / `hyperkd.sys` → Ring -1 drivers / support.
- `hyperhv.dll` → VMM core (**focus of the documented vulnerabilities**).
- `hyperevade.dll` → anti-VM-detection.

### Phase D — Source and diff against upstreams (the shortcut)
1. Extract/read `DenuoOwO_SRC.7z` (**reading**, not building).
2. Clone the **clean** upstreams: SimpleSvm (MIT), HyperDbg, EfiGuard (GPL-3.0).
3. **Diff** to separate **stock vs. custom**. The *custom* part concentrates the bypass logic and the
   **detection clues** (which CPUID/MSR values are spoofed, how the EPT hooks are installed, which
   syscalls are intercepted).
4. Document the "component → upstream → delta" mapping in `findings/`.

### Phase E — IOC extraction and findings
1. Consolidate IOCs (`docs/02` §3): hashes, driver/service names, registry keys, lifecycle strings,
   boot sequence.
2. Draft **YARA** (file-based) and **Sigma** (log-based) rules from what has been verified.
3. Report: confirmed mechanism, the Ring -1 vulnerability surface, and a **detection → remediation
   map**.

---

## 4. What this runbook does NOT do

- It does not execute binaries, does not load drivers, does not launch the game, does not run
  `VBS.cmd`.
- It does not compile or "fix" the bypass; the `SRC` is **read**, not **built**.
- It does not disable any system protection (remediation goes in the opposite direction; see
  `docs/04`).

If a phase appears to require executing something from the sample, **stop and ask**
(`CLAUDE.md` §8).
