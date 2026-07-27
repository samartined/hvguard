# 04 — Defensive tools specification

Roadmap and specs for the *out-of-the-box* tools. Two axes: **safeguard** (prevent/protect) and
**repair** (restore after execution), plus cross-cutting **detection**.

> **Design thesis:** the technique **depends on you turning off HVCI + Secure Boot** and on
> **loading an unsigned driver**. That is why effective defense is **minimal and precise**: secure
> and monitor those controls, detect the state changes, and be able to revert them. It doesn't take
> a complex tool; it takes the **correct** one. *[audit]*

Before generating code, confirm: **(1)** host **Intel (VMX)** vs **AMD (SVM)**; **(2)**
**PowerShell** vs. compiled/portable; **(3)** package extracted + **VM/WSL** ready, or set up the
environment first.

---

## Axis 0 — Detection (cross-cutting)

### T0. Hypervisor detector / "has this run?"
Combines platform signals and IOCs:
- **Hypervisor-present bit:** `CPUID.1:ECX[31]`. If set without an expected legitimate hypervisor
  (known Hyper-V/VBS) → suspicious.
- **Vendor leaf `0x40000000`:** identifies/fingerprints the hypervisor present.
- **VM-exit timing:** measure `RDTSC` deltas around `CPUID` (which forces a VM-exit). Anomalous
  latencies suggest Ring -1 interposition. *(Classic Blue Pill detection technique; interpret with
  care: noisy, better as a correlated signal, not a standalone one.)*
- **File/registry IOCs:** presence of `HKLM\SOFTWARE\ManageVBS`, of the binaries from `docs/02` §1,
  or of their hashes.
- **State of defenses:** Secure Boot off, `testsigning` on, VBS/HVCI not running (see commands in
  `docs/02` §4).

Output: verdict with **traced evidence** (which signal fired, observed value vs. expected).

---

## Axis A — Safeguard (prevent / protect)

### T1. Posture checker (start here)
**PASS/FAIL** report on the state that **defeats** the technique:
- Secure Boot **ON** (`Confirm-SecureBootUEFI`).
- `testsigning` **OFF** (`bcdedit`).
- VBS **running** and HVCI **running** (`Win32_DeviceGuard`: status `2`, services include `2`).
- Memory integrity **ON**.
Design: idempotent, no side effects, exit code based on the result, human-readable output + JSON to
feed into telemetry. **Does not touch the sample.** This is the first recommended deliverable.

### T2. HVCI enforcement + monitor (**heart of the defense**)
- **Enforce** HVCI/VBS via policy/registry (paths in `docs/02` §4) and leave it *enforced*.
- **Monitor**: scheduled task / event subscription that **alerts** if something disables HVCI/VBS,
  if `testsigning` appears, or if Secure Boot switches to off. This is the cleanest signal that
  someone has staged the technique.
- Optional: WDAC in a mode that prevents booting without the policy (defense in depth).

### T3. WDAC policy (blocking unsigned drivers)
Windows Defender Application Control that **prevents loading unsigned drivers** — exactly what the
technique needs to inject (`SimpleSvm.sys`/`hyperkd.sys`). With HVCI active, the block is
**hypervisor-enforced** (VTL1). Deliverable: policy template + deployment/audit procedure.

### T4. Telemetry / detection rules
- **Sysmon** (config): capture *Event ID 6* (driver load) with hash/signature.
- **Code Integrity** (`Microsoft-Windows-CodeIntegrity/Operational`): watch **3033/3077** (driver
  blocked by policy).
- **Sigma rules** for: unsigned driver load, appearance of `ManageVBS`, VBS/HVCI/Secure Boot state
  change, `bcdedit ... testsigning on`.
- **YARA** (file-based): VMM lifecycle names/strings (`docs/02` §3.1).

---

## Axis B — Repair (restore after execution)

### T5. Independent, auditable remediation
**Our own** reimplementation (do not run the crack's `VBS.cmd` — that was part of the initial
discomfort) of the restoration:
1. Re-enable **VBS/HVCI** (`DeviceGuard` registry; reboot).
2. `bcdedit /set testsigning off`.
3. Guide/enforce **Secure Boot ON** (a UEFI step; document that it is manual).
4. Remove any **leftover driver/service** if one was registered (`sc delete <name>`; cleanup in
   `System32\drivers` only if applicable) — by default DenuvOwO does **not** install a persistent
   service, but **verify it** (`driverquery`, Autoruns). *[audit]*
5. Clean up the tracking key `HKLM\SOFTWARE\ManageVBS`.
6. Check for leftovers from the **re-hosting mirror wrapper** (recent programs, browser extensions, Task
   Scheduler, startup).
7. **Final verification** with T1 (posture) + an offline Defender scan.

Design: every step with **logging**, **pre/post check**, and a *dry-run* mode that only reports.

### T6. Post-execution (residual) detector
Same as T0 but oriented toward **"this already ran and has already closed"**: look for
file/registry IOCs and confirm that the hypervisor is **no longer** loaded (DenuvOwO's lifecycle
unloads it when the game closes). *[audit]*

---

## Suggested build order

1. **T1 (posture)** + **T0/T6 (detection)** — safe, immediate, do not touch the sample.
2. **T4 (telemetry/Sigma/YARA)** — fed by the IOCs from the analysis (`docs/03` Phase E).
3. **T2 (HVCI enforcement+monitor)** + **T3 (WDAC)** — hard prevention.
4. **T5 (remediation)** — the most delicate; build with dry-run and verification.

## Quality criteria

- Everything **idempotent**, with **logging** and **exit codes**.
- **Dry-run** by default for anything that modifies state (T2, T3, T5).
- **Human-readable + JSON** output to integrate into a pipeline/SIEM.
- Every detection **traced to evidence**; every remediation with a **pre/post check**.
- **Nothing** that disables protections or depends on executing the sample.
