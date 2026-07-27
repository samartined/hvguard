# Analysis summary — defensive forensic session (DenuvOwO / ElAmigos)

**Date:** 2026-07-13 · **Nature:** blue team / defensive forensics · **Golden rule respected:** the sample was never executed.

This document consolidates what was **verified first-hand** in this session. It complements (does not replace) the context docs `01`–`05`.

---

## 1. Identity and provenance of the sample
- Artifact: a ~103.5 GB **UDF** ISO, pirated release by **ElAmigos**, obtained through a
  third-party re-hosting mirror (not named).
- ⚠️ **Chain of custody:** the sample actually analyzed was an **Assassin's Creed _Shadows_**
  release. Earlier drafts of `01`/`05`/`README` named a different title; those now omit the title
  entirely, since it identifies a download and is irrelevant to the defence. Same family in either
  case (ElAmigos + DenuvOwO hypervisor bypass).
- Target host for the defense (confirmed by the user): **AMD (SVM/AMD-V)** → key bypass driver = `SimpleSvm.sys`.
- SHA-256 hashes of the distribution media were recorded during Phase A but are **not published**:
  they identify one pirated download rather than a threat. `findings/hashes.csv` therefore ships
  only genuine detection IOCs.

## 2. Container structure (verified)
```
UDF ISO
 └─ Inno Setup 5.5.x  (setup.exe stub PE32-x86, SetupLdr signature REMOVED by ElAmigos;
    │                  setup-0.bin = Inno data, setup-1.bin = slice)
    ├─ tmp\  = installer toolchain (unarc.dll, ISDone.dll, cls-lolz*, facompress*, CLS-srep, srep64.exe, arc.ini)
    ├─ app\  = encrypted files (icon, _Info.txt)  ← require the installer password
    └─ FreeArc payload  (elamigos-1..4.bin, magic "ArC\x01")
        └─ **AES-256/CTR ENCRYPTED** + LOLZ/SREP/facompress codecs   ← contains the DenuvOwO binaries
```
Method of the first block read from the FreeArc archive: `lzma:1mb:normal:bt4:32+aes-256/ctr:n1000:…`

## 3. Phase A — inventory and classification
- Deliverables: `findings/hashes.csv`, `findings/inventory-report.md`.
- Tool: `tools/phase-a-inventory.py` (read-only, no dependencies).

## 4. Installer toolchain triage — **clean**
- Deliverable: `findings/toolchain-triage.md` · tool: `tools/pe-triage.py`.
- The 13 binaries in `tmp\` are the **standard FreeArc/ISDone** toolchain (2012-2018): no network/injection/persistence APIs, normal entropy, exports consistent with codecs.
- Reputation by hash: `srep64.exe` = **genuine SuperREP** (known on Hybrid-Analysis); `unarc.dll`/`facompress.dll` flagged **clean** by AV in public repack analyses.
- **Conclusion (re-hosting mirror question):** the machinery that runs during installation **shows no dropper**. *Caveat:* static/heuristic; does not rule out an obfuscated payload.

## 5. Extraction of the DenuvOwO binaries — **not achieved (cryptographic wall)**
- The FreeArc payload is **encrypted with AES-256**. ElAmigos embeds the key in the installer, and it is only released **when `setup.exe` is run** (installation) — a red line.
- The `install_script.iss` (which would carry the key) could not be extracted: the modified Inno loader defeated innoextract and innounp.
- Verified first-hand: the open-source `unarc` was compiled (`github.com/xredor/unarc`, audited clean code), and reading the header returned the method `…+aes-256/ctr` → **encryption confirmed**.
- **Verdict:** statically extracting these binaries is **cryptographically infeasible without running the installer**. This is not a limitation of tooling or of caution. No unverified scene-release binaries were pursued as a route around it.

## 6. Is it malicious? (triage objective)
- **The crack itself:** dissected first-hand in public RE reports (0xPacman, RD945, haise0 — `doc 05`): **no general-purpose malware** (no C2/exfiltration/mining). *Caveat:* static analyses; the real danger is not a trojan but (a) the **Ring -1 vulns in `hyperhv.dll`** (privilege escalation without admin) and (b) that it **tears down kernel defenses** while running.
- **The re-hosting mirror's installer:** its toolchain came out **clean** in our triage; the payload is encrypted by ElAmigos itself (standard packaging, no indication that the mirror trojanized it).

## 7. Defense delivered (see `defense/`)
Suite `T0`–`T5` + `T4` telemetry, unified with the contributions of a parallel script (`nointegritychecks`, Vulnerable Driver Blocklist, Smart App Control, BYOVD list, driver quarantine). Details and deployment order in `defense/README.md`. Pending: validation on a disposable VM/Windows environment (not on the production host).
