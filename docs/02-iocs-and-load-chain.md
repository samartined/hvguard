# 02 — IOCs, Components, and Load Chain

Raw material for **detection** and **repair**. Everything listed here comes from the session: the
official sample sheet *[official]* and public RE reports *[audit]*. **The concrete hashes must be
calculated from the real sample** (analysis phase); here we list **names and behaviours** as
stable indicators.

> Reminder: these indicators are for **defensive** purposes (detection/cleanup). The repo does not
> distribute the binaries.

---

## 1. Component inventory (roles)

| File | Likely role | Notes |
|---|---|---|
| `hypervisor-launcher.exe` | **Loader** in user-land: orchestrates loading of the driver + hypervisor and launches the game | Entry point from the "desktop icon" |
| `SimpleSvm.sys` | **Hypervisor driver (AMD SVM)** — Ring -1 | Base: SimpleSvm (MIT, S. Tanda). Unsigned → requires DSE off |
| `hyperkd.sys` | Support **kernel driver** | *[audit]* "open source, not on GitHub" |
| `hyperhv.dll` | **VMM core** (based on HyperDbg) | **Contains the documented Ring -1 vulnerabilities** |
| `hyperevade.dll` | **Evasion layer** (anti-VM-detection) | Spoofing/concealment against Denuvo checks |
| `VBS.cmd` | **Security toggle script** | Option 1 = disable VBS; **Option 3 = revert** via `ManageVBS` |
| `DenuvOwO.nfo`, `_Info.txt` | Documentation/instructions | Read **as text**, never execute |
| `DenuoOwO_SRC.7z` | **Bypass source code** | For reading/diffing against upstreams |

> Components seen in sibling cracks (MKDev/Kirigiri variant), useful as family indicators:
> **EfiGuard** (GPL-3.0, UEFI bootkit that disables PatchGuard/DSE), **Goldberg Steam Emu** (LGPL), and
> **ColdClientLoader** (Steam emulation/loading). *[audit]* In the AC4 sample the underlying DRM is
> **Ubisoft Connect**, so the store emulation layer may differ.

---

## 2. Load procedure (per official sample sheet) *[official]*

1. Install the game.
2. (Prerequisite) **CPU virtualization enabled in BIOS** (VT-x/AMD-V).
3. Run `VBS.cmd` **as Administrator** → press **1** → **reboot**.
4. On the **next boot**, press **F7** when the window appears → *Disable Driver Signature
   Enforcement* (**DSE off** for that boot only).
5. Launch from the **desktop icon** (`hypervisor-launcher.exe`).
6. Per-session persistence: it works **until reboot/shutdown**; to play again, repeat
   `VBS.cmd` → 1 → reboot → F7 → icon.

**Forensic reading of the sequence:** step 3 **disables VBS** (persistent until reverted); step
4 **disables DSE** (only for that boot); step 5 **loads the unsigned driver** and **virtualizes** the
OS. The **absence** of EfiGuard in this flow implies that **a normal reboot restores DSE**.

---

## 3. IOCs by category

### 3.1 Files
- Names from the table above (`.sys` drivers, `hyper*.dll` DLLs, `hypervisor-launcher.exe`,
  `VBS.cmd`, `DenuvOwO.nfo`).
- **Analysis action:** calculate the **SHA-256** of each one and build a hash set; check the
  Authenticode signature (the `.sys` files are expected to be **unsigned** or have an invalid signature).
- Lifecycle strings expected in the VMM (from SimpleSvm/HyperDbg): messages such as *"Attempting to
  virtualize the processor" / "The processor has been virtualized" / "…de-virtualized" / "SVM is not
  fully supported on this processor"*. *[audit]* Useful for **YARA** rules over files.

### 3.2 Registry
- **`HKLM\SOFTWARE\ManageVBS`** — **tracking** key created by `VBS.cmd` itself so it can
  revert. Its **presence** is a direct IOC that the technique was prepared/used. *[audit]*
- Altered states to watch (see §4 for paths):
  - VBS/HVCI disabled in `...\DeviceGuard`.
  - `testsigning` (BCD) enabled (*test signing* variant).

### 3.3 Boot / system configuration
- **Secure Boot = OFF** (prerequisite of the technique).
- **DSE disabled** (via F7 at boot or via `testsigning`).
- (EfiGuard variant) unsigned UEFI boot component interposing itself — only if that variant was
  used.

### 3.4 Behaviour / runtime (for telemetry)
- **Unsigned kernel driver load** → **Sysmon Event ID 6** and **Code Integrity** events.
- **Hypervisor** presence where it should not be (the *hypervisor-present* bit set with no legitimate
  hypervisor expected; vendor leaf `0x40000000`).
- **Timing** anomalies in instructions that force a VM-exit (`CPUID` latency).

---

## 4. State-verification commands (Windows)

Basis for both the **detector** and the **posture checker** (`docs/04`). Run in a console
**with privileges**.

**Secure Boot:**
```powershell
Confirm-SecureBootUEFI      # True = active (desired). False = disabled (IOC)
```

**Test signing and BCD:**
```cmd
bcdedit                      # look for 'testsigning  Yes' (IOC) and the state of 'hypervisorlaunchtype'
```
Remediation: `bcdedit /set testsigning off`

**VBS / HVCI running:**
```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning, SecurityServicesConfigured
# VirtualizationBasedSecurityStatus: 2 = running (desired)
# SecurityServicesRunning: include 2 = HVCI running (desired)
```
Also: `msinfo32` → "Virtualization-based security: Running" and "…services configured/running:
Hypervisor enforced Code Integrity".

**Relevant registry paths (VBS/HVCI):**
```
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity  = 1
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 1
```

**Crack tracking key (IOC):**
```
HKLM\SOFTWARE\ManageVBS      # its presence indicates preparation/use of the technique
```

**Loaded drivers / services (leftovers):**
```cmd
driverquery /v               # review unsigned drivers / suspicious paths
```
```powershell
Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' }
```
Boot inspection recommended with **Autoruns** (Sysinternals): *Drivers* and *Logon* tabs.

---

## 5. Logs and Event IDs for detection

- **Sysmon** — *Event ID 6* (Driver loaded): signature/hash of the loaded driver. Filter by unsigned
  drivers or by the names from §1.
- **`Microsoft-Windows-CodeIntegrity/Operational`** — events **3033** / **3077** when a driver that
  does not comply with the integrity policy is **blocked** (a signal that an unsigned driver attempted
  to load). Highly relevant with WDAC/HVCI active.
- **`Microsoft-Windows-DeviceGuard`** — VBS/HVCI state changes.
- Changes in **BCD** / Secure Boot: correlate with boot configuration events.

From this, **Sigma rules** can be derived for an endpoint (see `docs/04`, telemetry axis).
