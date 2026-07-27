# Phase A - Inventory and chain of custody of the sample

- **Tool:** `phase-a-inventory` v1.0.0
- **Start (UTC):** 2026-07-12T19:56:15Z  **End (UTC):** 2026-07-12T21:08:53Z
- **Sample root:** `<sample-root>`  *(mounted READ-ONLY)*
- **Output:** `findings/hashes.csv`, `findings/inventory-report.md`
- **Hash mode:** ALL (--hash-all)

> **Static, read-only** analysis. No sample binary is executed or loaded. Windows PEs cannot boot on this Linux VM (zero execution risk).

## Totals

- Files: **9**  |  Total size: **103.56 GB** (103557807002 B)
- Fully hashed (SHA-256 OK): **9**
- Hash skipped due to size: **0**  |  Read errors: **0**
- Files flagged as **bypass-relevant (IOC)**: **0**

## Breakdown by category

| Category | Nº | Size |
|---|---:|---:|
| archive-freearc | 4 | 103.55 GB |
| pe-exe | 1 | 1.32 MB |
| installer-inno-slice | 1 | 1.19 MB |
| installer-inno-data | 1 | 154248 B |
| image | 1 | 149284 B |
| config | 1 | 69 B |

## Bypass-relevant artifacts (triage focus)

_No file matched the bypass IOC patterns at this root._ Check whether the sample is inside a sub-container (installer, nested 7z) that has not been extracted yet.

## High-entropy files (possible packing/encryption, entropy ≥ 7.2)

| Path | Category | Size | Entropy | Scope |
|---|---|---:|---:|---|
| `elamigos-1.bin` | archive-freearc | 81.19 GB | 8.000 | FULL |
| `elamigos-2.bin` | archive-freearc | 10.82 GB | 8.000 | FULL |
| `elamigos-3.bin` | archive-freearc | 11.20 GB | 8.000 | FULL |
| `elamigos-4.bin` | archive-freearc | 344.00 MB | 8.000 | FULL |
| `setup-1.bin` | installer-inno-slice | 1.19 MB | 8.000 | FULL |
| `setup-0.bin` | installer-inno-data | 154248 B | 7.999 | FULL |

## Next step

- **Phase B (PE triage)** on the relevant artifacts: headers, Authenticode signature, imports (ZwLoadDriver, RegSetValueEx, VMX/SVM intrinsics, network/injection) and exports (`hyperhv.dll`/`hyperevade.dll`). Requires installing `pefile` (and `capstone` for Phase C).
- If the bypass components do not appear here, they are inside an installer or a nested `.7z`/`.zip`: locate it by name and extract it to a working directory (`/tmp` or `~/work`, **never** over the sample) to inventory it separately.
