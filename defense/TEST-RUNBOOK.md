# Validation runbook — by hand on a disposable Windows machine

Goal: **runtime-test** the T0-T5 suite (it has never been executed; the analysis VM is Linux). This is
done on a **disposable Windows machine with snapshots**, reproducing the *state* the technique leaves
behind **without running the crack**.

> Golden rule of this runbook: **nothing from the sample (ISO/crack) enters this VM.** Only the
> `defense/` folder and manual commands.

## 0. Preparation
- **Windows 10/11 Pro/Enterprise** VM. For VBS/HVCI/WDAC to actually work: **nested** virtualization
  enabled on the hypervisor (VirtualBox: `VBoxManage modifyvm <vm> --nested-hw-virt on`; VMware:
  "Virtualize Intel VT-x/EPT or AMD-V/RVI"). *Without nested virtualization, the script LOGIC still
  validates the same way (they read/write the registry and report); only "VBS running" will come back
  false — that is not a bug.*
- Copy the `defense/` folder to the VM (e.g. `C:\def\`).
- **"CLEAN" snapshot.**
- PowerShell **as Administrator**:
  ```powershell
  Set-ExecutionPolicy -Scope Process Bypass -Force
  cd C:\def
  ```

## Phase 1 — Read-only (zero risk). Validates the read paths.
```powershell
.\T1-posture-check.ps1
.\T0-hv-detector.ps1
```
**Expected (healthy VM):** T1 → `PASS` (or `INCONCLUSIVE` if you were not admin; `WARN` on Secure Boot /
blocklist = normal, not a failure). T0 → `CLEAN`.
👉 Note down **any exception or error** — that is a bug to fix.

## Phase 2 — Manually fabricate the "compromised" state (WITHOUT the crack)
"PRE-COMPROMISE" snapshot. Then:
```powershell
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
New-Item "HKLM:\SOFTWARE\ManageVBS" -Force | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
# (or: Windows Security > Device security > Core isolation > Memory integrity > Turn off)

# DRIVER decoy fixture (registers a kernel service under the bypass's name; does NOT start it):
sc.exe create SimpleSvm binPath= C:\Windows\Temp\denuvowo_fake.sys type= kernel start= demand
# FILE decoy fixture:
New-Item "$env:USERPROFILE\Downloads\SimpleSvm.sys" -ItemType File -Force | Out-Null
```
**Restart** (so testsigning / HVCI-off take effect). Do not start the decoy service.

After restarting:
```powershell
cd C:\def ; .\T0-hv-detector.ps1
```
**Expected:** `DETECTED` — testsigning ON, nointegritychecks ON, HVCI not running, `ManageVBS`
present, `SimpleSvm` driver registered, `SimpleSvm.sys` file in Downloads. Each finding with its
evidence.

## Phase 3 — Remediate (T5) and verify
```powershell
.\T5-remediation.ps1                 # DRY-RUN: shows what it would do, without touching anything
.\T5-remediation.ps1 -Apply          # applies it (confirms each change; add -Force to skip prompts)
```
**Restart.** Then:
```powershell
cd C:\def ; .\T1-posture-check.ps1   # Expected: PASS (Secure Boot may stay WARN, that is normal)
```
Check that T5: turned testsigning/nointegritychecks **off**, re-enabled VBS/HVCI (registry), turned on
the **blocklist**, deleted `ManageVBS`, and **quarantined** the decoy driver (`start=disabled`). To test
deletion instead of quarantine: `.\T5-remediation.ps1 -Apply -RemoveResidualDriver`.
Manual fixture cleanup if needed: `sc.exe delete SimpleSvm`.
👉 **Restore the "CLEAN" snapshot** before the next phase.

## Phase 4 — T2 (enforce HVCI/VBS + monitor)
```powershell
.\T2-hvci-enforce-monitor.ps1                          # current state
.\T2-hvci-enforce-monitor.ps1 -Enforce -InstallMonitor # enforces registry + creates task/event
Get-ScheduledTask -TaskName HVGuard-PostureMonitor     # must exist
Start-ScheduledTask -TaskName HVGuard-PostureMonitor
Get-EventLog -LogName Application -Source HVGuard -Newest 5   # events 7000 (OK) / 7001 (drift)
```
**Drift alert** test: `bcdedit /set testsigning on` → `Start-ScheduledTask -TaskName
HVGuard-PostureMonitor` → confirm a **7001** event.
👉 **Restore the "CLEAN" snapshot.**

## Phase 5 — T3 (WDAC) — ⚠️ AUDIT ONLY first (can prevent booting)
```powershell
.\T3-wdac-block-unsigned-drivers.ps1 -Audit
```
**Restart.** Use the system normally and review `Microsoft-Windows-CodeIntegrity/Operational` → **3076**
events ("would be blocked"). If NOTHING critical would be blocked, *only then* consider `-Enforce`.
Check that the policy is kernel-only: `pwsh -NoProfile -c '$ExecutionContext.SessionState.LanguageMode'`
must still print `FullLanguage`, and `-Status` must show no `UMCI` warning.
Rollback: `.\T3-wdac-block-unsigned-drivers.ps1 -Remove` (also removes a policy deployed by T3 < 1.1.0;
a second `-Remove` must report `ERROR`, not `APPLIED`).
👉 **Restore the "CLEAN" snapshot.** (That is why you snapshot first and audit first.)

## Phase 6 — T4 telemetry (optional)
```powershell
# Sysmon (download it from Sysinternals):
sysmon64.exe -accepteula -i C:\def\telemetry\sysmon-hv-bypass.xml
# generate an event (e.g. the 'bcdedit /set testsigning on' from phase 2) and look for it in:
#   Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
# Sigma: convert with sigma-cli for your SIEM.  YARA: yara -r C:\def\telemetry\yara\denuvowo.yar <folder>
```
👉 **Restore the "CLEAN" snapshot** when done.

---

## Critical points
- **Snapshot before every destructive phase; restore afterward.**
- **Never** bring in the ISO or run the crack to "create" the state — it is reproduced by hand (phase 2).
- **Send me any error, exception or odd output.** This is 600+ lines of PowerShell that has never been run; something will fail, and that is exactly what needs fixing.
