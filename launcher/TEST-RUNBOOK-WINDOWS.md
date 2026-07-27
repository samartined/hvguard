# TEST-RUNBOOK — HVGuard (Windows)

Step-by-step test guide for the **HVGuard** launcher. It separates what is **safe to test on any
Windows machine** (read-only) from what **must only be tested on a disposable Windows VM with a
snapshot** (state changes). Follow the order.

> **Guardrails (CLAUDE.md, non-negotiable).**
> - HVGuard **never** executes, installs or launches anything from the crack (not the game, not
>   `setup.exe`, not `VBS.cmd`). In "Watch while you play" **you** launch it; the app only observes
>   before/after.
> - HVGuard **never** disables protections. Everything goes toward **re-enabling/hardening**.
> - `T3 -Enforce` (real driver blocking) is **not** exposed as a single click: the GUI only runs
>   `T3 -Audit`.
> - To **simulate** a compromised machine (Part B), the *footprint is reproduced by hand* in a VM;
>   the crack is **never** executed to create that state.

---

## 0. Requirements

- Windows 10/11. **Windows PowerShell 5.1** (always present) or **PowerShell 7** (`pwsh`). Either works.
- The `launcher/` folder next to `defense/` and `findings/` (the repo layout). HVGuard locates the
  engine by looking for `defense\*.ps1` from the root.

---

## 1. Validation status (already run, 2026-07-13, on real Windows, read-only)

| Test | Result |
|---|---|
| `Invoke-HvgTool T1/T0/T5(dry)/T7` returns deserialized JSON (pwsh 7 **and** WinPS 5.1) | ✅ |
| `Shell.xaml` parses and the 21 expected names resolve (STA, both hosts) | ✅ |
| `HVGuard.ps1 -SelfTest` → window **renders**, degrades to read-only, bilingual ES/EN | ✅ `rendered=True` |
| Discovers and initializes the **5 modules** with no errors (`modules=5 initErrors=0`, both hosts) | ✅ |
| **T7** console: hash IOC (CSV) + name IOC (`SimpleSvm.sys`,`VBS.cmd`) → `KNOWN-THREAT`; unsigned `.sys` → `SUSPECT`; **clean signed PE (`notepad.exe`) → `CLEAN` with no false positive** | ✅ correct exit 1/0 |
| M1 combines T1+T0 → status light; M2 dry-run; M4 delta/correlation; M5 folder scan | ✅ (working harness) |
| **`dist/HVGuard.exe`** self-contained: self-extracts `launcher/`+`defense/`+`findings/` and starts the GUI | ✅ `exit=0 rendered=True modules=5` |
| **À la carte repair**: `T5 -Only` is a **fail-closed** allowlist (20 assertions against T5's real code: unticked items are NOT applied; items without a declared ID aren't either; `WOULD_FIX`→`SKIPPED`) | ✅ 20/20 |
| **Choice GUI (M2)**: one checkbox per group, `R9` multi-file → **1** checkbox, `R7` manual **outside** the checkboxes, correct `-Only` string when unticking, ES+EN explanations for the 11 steps, read-only disables everything | ✅ 26/26 |
| **R1b**: detects VBS "enabled, not running" caused by requiring Secure Boot when it is unavailable, and unblocks it (measured on a real host: `FALTAN 2=SecureBoot`) | ✅ |

Pending (Part B): full **compromised→repair→green** cycle with a real `-Apply`, `T2 -Enforce`,
`T3 -Audit` deployed, and an **Authenticode signature** on the `.exe` (the packaging is already done:
`dist/HVGuard.exe`). **Only on a disposable VM** or on the target endpoint under control.

---

## 2. Part A — SAFE tests (any Windows machine, read-only)

### A1. Start the GUI
- **`dist\HVGuard.exe`** (double-click): a single self-contained file; it self-extracts to
  `%LOCALAPPDATA%\HVGuard\<build>\` and starts. This is the way to share it. (For development, also
  `launcher\HVGuard.cmd` or
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File launcher\HVGuard.ps1`.)
- **Expected:** the UAC prompt appears. Accept it → HVGuard window (gray status light "NOT CHECKED",
  5 tabs).
- **Degraded mode:** launch it again and **cancel** the UAC prompt → the app still opens, in
  **read-only mode** (the bottom bar shows it; *Repair*/*Harden* disabled).

### A2. Automated render (no interaction)
```powershell
pwsh -NoProfile -STA -File launcher\HVGuard.ps1 -SelfTest -SelfTestMs 1500
# Expected: "SELFTEST rendered=True ... modules=5 initErrors=0"
# Optional screenshot:  ... -SelfTest -Shot "$env:TEMP\hvguard.png"

# From the .exe (it's a GUI -> uses Start-Process -Wait; output goes to %TEMP%\hvguard-selftest.out):
Start-Process dist\HVGuard.exe -ArgumentList '-SelfTest','-SelfTestMs','1500' -Wait; Get-Content $env:TEMP\hvguard-selftest.out
```

### A3. Check (M1, read-only)
- **Check** tab → **Check now** button.
- **Expected:** the status light switches to PROTECTED / AT RISK / COMPROMISED and "View details"
  lists the evidence (T1 checks + T0 alerts). On a healthy machine with no decoys: **PROTECTED**.
- *Note:* if you have files named `SimpleSvm.sys`/`VBS.cmd` in `Downloads`/`Desktop`/`%TEMP%`, T0 will
  flag them (that is correct: they are name-based IOCs).
- **Copy to investigate:** all result/evidence text is **selectable** (drag and `Ctrl+C`), and every
  card has **right-click → Copy** (copies name + path + signals). Useful for looking up a
  threat/path/hash online.
- **Responsiveness:** scans run in the background (the status bar shows the elapsed seconds); the
  window does not freeze and every tab has a vertical scrollbar.

### A4. Scanner (M5) and Folder (M4) on HARMLESS decoys
Create a test folder with decoys (they are not the crack; they are empty/text files):
```powershell
$d = "$env:TEMP\hvg-test"; New-Item -ItemType Directory -Force $d | Out-Null
Set-Content "$d\VBS.cmd" "echo decoy"                    # name-based IOC
[IO.File]::WriteAllBytes("$d\SimpleSvm.sys", [byte[]](1..64))  # name-based + .sys IOC
Copy-Item C:\Windows\System32\notepad.exe "$d\clean.exe" # signed PE -> CLEAN
```
- **M5 Scanner** → *Post-install* mode → path = `%TEMP%\hvg-test` → **Analyze**.
  - **Expected:** ⛔ **KNOWN-THREAT** (from `VBS.cmd`/`SimpleSvm.sys`), `clean.exe` does not show up
    (CLEAN).
  - Select *Pre-install* → the mandatory **blind-spot banner** appears.
  - The "online reputation (hash only)" checkbox is **off** by default (it makes no network call
    unless you tick it and `HVGUARD_VT_API_KEY` exists).
- **M4 Folder** → path = `%TEMP%\hvg-test` → **Analyze this folder**: correlates components with your
  posture. Delete the folder when done: `Remove-Item $d -Recurse -Force`.

### A5. Repair in simulation mode (M2, without applying) — **à la carte repair**
- **Repair** tab → **Show what it would do (no changes)**.
- **Expected (healthy machine):** "Your PC is already healthy: nothing to repair"; **Apply** button
  disabled. (In read-only mode, *Apply* is always disabled, with a warning.)
- **Expected (something to repair):** **one checkbox per item to restore**, all ticked by default,
  with badges (*Needs a restart* / *Takes effect now* / *Key against the bypass*), a **"What is
  this?"** expander that explains in plain language **WHAT IT IS / WHY IT MATTERS / WHAT I WILL DO**,
  and the actual measured state. **Select all** / **Select none** buttons; the main button shows a
  counter (**"Apply selected (N)"**) and is disabled if nothing is ticked.
- **What is NOT offered as a checkbox:** steps the tool **cannot** perform (R7 Secure Boot, or a
  **running** driver) are listed separately under *"This CANNOT be automated: you have to do it
  yourself"*, with guidance. Offering a checkbox for something impossible would be misleading.
- **Contract with the engine:** on apply, the GUI calls `T5 -Apply -Force -Only <ticked ids>`. `-Only`
  is a **fail-closed allowlist**: anything not ticked is left untouched and reported as `SKIPPED` (and
  if a change did not declare its ID, it would not be applied either while the filter is active).
  Without `-Only`, T5 keeps its classic behavior (applies everything needed).
- Grouping: `R6`/`R9` can affect **several** drivers/files and are shown as a **single** checkbox that
  lists the affected items inside.

### A6. T7 on the console (optional, reproduces the validation)
```powershell
pwsh -NoProfile -File defense\T7-target-scan.ps1 -Target "$env:TEMP\hvg-test"
pwsh -NoProfile -File defense\T7-target-scan.ps1 -Target C:\Windows\System32\notepad.exe   # -> CLEAN (exit 0)
```

---

## 3. Part B — Tests that CHANGE STATE (DISPOSABLE Windows VM with a snapshot ONLY)

> **Take a snapshot before you start.** These tests modify system protections. **Never** run them on
> an uncontrolled work machine, and **never** run the crack to create the state: the **footprint is
> simulated by hand**.

### B1. Simulate the "compromised" state (by hand, in the VM)
Run this in an **Administrator** console on the VM:
```powershell
# (1) Registry IOC left behind by the crack's VBS.cmd
New-Item -Path 'HKLM:\SOFTWARE\ManageVBS' -Force | Out-Null
# (2) Turn off Memory integrity (HVCI) via the registry  [requires a restart]
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -PropertyType DWord -Value 0 -Force | Out-Null
# (3) Weaken driver signing  [requires a restart]
bcdedit /set testsigning on
# (4) Component decoy in a "game folder"
$g = 'C:\Games\Demo'; New-Item -ItemType Directory -Force $g | Out-Null
[IO.File]::WriteAllBytes("$g\SimpleSvm.sys", [byte[]](1..128))
Restart-Computer   # applies (2) and (3)
```
After restarting, Memory integrity will be **OFF** and `testsigning` **ON** (a footprint equivalent to
the one the technique leaves, **without** having run the crack).

### B2. Detect → Repair → Green (M1 → M2)
1. Open HVGuard (Administrator). **Check** → **COMPROMISED** (HVCI off, testsigning on, ManageVBS IOC).
2. **Repair** → **Show what it would do** → review the steps in plain language → **Apply** → confirm.
   - **Expected:** re-enables HVCI/VBS, `testsigning off`, deletes `ManageVBS`, turns on the
     blocklist; warns that **a restart is required**.
3. **Restart** → **Check** again → **PROTECTED**.

### B3. Harden and watch (M3)
- **Harden now** (T2 `-Enforce -InstallMonitor`): forces HVCI/VBS and creates the
  `HVGuard-PostureMonitor` task. Verify:
  ```powershell
  Get-ScheduledTask -TaskName HVGuard-PostureMonitor
  # Trigger a check and look at Event Viewer (Application, source "HVGuard"): 7000=compliant / 7001=drift
  Start-ScheduledTask -TaskName HVGuard-PostureMonitor; Get-WinEvent -LogName Application -MaxEvents 5 | ? ProviderName -eq 'HVGuard'
  ```
- **Audit drivers (WDAC)** (T3 `-Audit`): deploys the policy in **audit** mode (does not block).
  Check `Microsoft-Windows-CodeIntegrity/Operational` (events **3076/3077**) before you consider
  enforcing it. Moving to **real blocking** is an **advanced, manual** step (risk of failing to boot);
  HVGuard does not do it.

### B4. Launch delta (M4) — without running the crack
1. **Game folder** → path = `C:\Games\Demo` → **Take snapshot BEFORE playing**.
2. Simulate "something turned off a defense" (instead of launching the crack): in another admin
   console, `New-ItemProperty ...HypervisorEnforcedCodeIntegrity Enabled 0` **or** stop enforcing and
   turn off HVCI from Windows Security, and **restart** (or simulate without restarting by turning off
   VBS via policy and re-evaluating).
3. **I closed the game → snapshot AFTER**. The BEFORE snapshot is saved to disk
   (`%ProgramData%\HVGuard\launch-baseline.json`), so it **survives the restart** the crack requires:
   you can restart between BEFORE and AFTER, reopen HVGuard, and M4 will show "BEFORE snapshot saved
   on …" with the button ready to compare. Also, every green "Check" saves an automatic baseline.
   - **Expected:** "The launch DEGRADED your defenses: HVCI (C4) before PASS → after FAIL", and if you
     created `ManageVBS`, "The ManageVBS key appeared". Includes the **honest limit** (the hypervisor
     is invisible while running).

### B5. Revert
- Restore the VM **snapshot**, or repair with M2 and `bcdedit /set testsigning off` + re-enable HVCI +
  `Remove-Item HKLM:\SOFTWARE\ManageVBS`. Remove WDAC with `defense\T3-...ps1 -Remove` if you deployed
  it.

---

## 4. Notes
- **Visible console:** when launched via `.cmd`, HVGuard hides the host console; a brief flicker may
  be visible. A consoleless package (Phase 6) removes it.
- **Signing:** the `.ps1`/`.cmd` files are not signed in the repo. To distribute, add an Authenticode
  signature and document SmartScreen's *"More info → Run anyway"* prompt.
- **Language:** it detects the system culture; change it with the selector at the top right (it
  redraws the panels in the chosen language).
