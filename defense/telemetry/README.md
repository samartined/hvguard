# T4 — Telemetry and detection rules

Detection of the hypervisor bypass (**DenuvOwO** family) at the endpoint/SIEM level. All content is derived
from **public IOCs** (doc 02, RE reports from doc 05) and upstream OSS projects — **never from the
crack binary**. Marked for **tuning** if samples ever arrive through a legitimate channel (VT
Intelligence / MalwareBazaar).

## Contents

| File | What it covers | Event source |
|---|---|---|
| `sysmon-hv-bypass.xml` | Sysmon config: driver load (EID 6), processes (EID 1), registry (EID 12/13), files (EID 11) | Sysmon |
| `sigma/win_driverload_hv_bypass.yml` | Bypass driver or unsigned kernel driver | Sysmon EID 6 (`driver_load`) |
| `sigma/win_registry_managevbs.yml` | Creation of `HKLM\SOFTWARE\ManageVBS` (direct IOC) | Sysmon EID 12/13 |
| `sigma/win_bcdedit_weaken_boot.yml` | `bcdedit` enabling testsigning / turning off the hypervisor | Sysmon EID 1 |
| `sigma/win_codeintegrity_driver_blocked.yml` | Driver blocked by policy (signal that the defense is active) | CodeIntegrity/Operational 3033/3077 |
| `sigma/win_vbs_hvci_disabled.yml` | DeviceGuard set to 0 (VBS/HVCI turned off) | Sysmon EID 13 (`registry_set`) |
| `sigma/win_hv_bypass_launcher.yml` | Execution of `hypervisor-launcher.exe` / `VBS.cmd` | Sysmon EID 1 |
| `yara/denuvowo.yar` | **File-based** rules: SVM/HyperDbg strings + component names | file scanning |

## Deployment

**Sysmon** (requires admin):
```
sysmon64.exe -accepteula -i sysmon-hv-bypass.xml     # install
sysmon64.exe -c sysmon-hv-bypass.xml                 # update config
```
This is a **fragment**: combine it with your baseline Sysmon config (e.g. SwiftOnSecurity) so you don't lose general coverage.

**Sigma** — convert to your backend with [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli):
```
sigma convert -t <splunk|esql|kusto|...> -p sysmon defense/telemetry/sigma/
```
Event IDs and channels are in each rule; adjust the `logsource`/pipeline to your SIEM.

**YARA** (file scanning, **not** live memory):
```
yara -r defense/telemetry/yara/denuvowo.yar <path_or_resource>
```

## Notes
- The rules prioritize **high fidelity** on the most specific IOCs (ManageVBS, component
  names, boot weakening). The "unsigned driver" and "DeviceGuard set to 0" rules can generate
  false positives in environments with third-party drivers: **tune your exclusions**.
- The CodeIntegrity 3033/3077 rule is a **signal that the defense worked** (a driver was blocked):
  use it to confirm that HVCI/WDAC (T2/T3) are cutting off the attempt.
- On **AMD/SVM** architecture (target host), the main driver to watch is **`SimpleSvm.sys`**.
