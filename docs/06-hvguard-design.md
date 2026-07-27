# 06 — Execution plan: Community launcher "HVGuard"

> **Nature of this document:** this is a **plan for other agents/sessions to execute**. Whoever
> wrote it (session of 2026-07-13) **only plans**; they do not implement. Before touching anything, the
> executor MUST read `CLAUDE.md`, `HANDOFF.md`, and `docs/04-defensive-tools-spec.md`.
>
> **State of the project this builds on:** defensive suite `T0–T5` **built and validated
> end-to-end on real Windows** (see `HANDOFF.md` §5). This launcher **does not reinvent** that logic: it
> **wraps** it. The `.ps1` files in `defense/` are the **engine** and the **single source of truth**.

---

## 0. One-sentence summary

Build a **Windows desktop application, with a simple, plain-language graphical interface**,
that self-elevates to Administrator and puts all the defensive work already validated (check, repair,
harden, watch) within reach of a **non-technical** user, **plus** two new capabilities requested by
the user: **(A)** tracking centered on the **game folder**, and **(B)** a **known-threat scanner**
over the executable/folder before the user installs or launches it.

Proposed product name: **HVGuard** (already in use: task `HVGuard-PostureMonitor`, folder
`%ProgramData%\HVGuard\`). Keep it for brand consistency.

---

## 1. Objective and philosophy (why this exists)

- **Audience:** the average member of the piracy community, with no technical knowledge. They are not
  going to open PowerShell as administrator, read a table of verdicts, or interpret "HVCI".
- **Goal (harm reduction):** that this person, **if they are going to use the crack anyway**, can at
  least **know what state their PC is in, repair it, and harden it** with a double-click, without
  compromising their security and privacy out of ignorance.
- **Guiding design principle — NEVER give false security.** This tool is a defensive assistant,
  **not** an endorsement that the crack is safe, nor an invitation to run it. "Green" never
  means "it's safe"; it means "I have not found **known** threats." All UI *copy* is
  written with that honesty. (See §5.4.)
- **Translation, not false simplification:** the UI translates what the engine does into human
  language, but it **never lies about or hides** the residual risk.

---

## 2. Critical analysis of the user's two ideas ("take a hard look at whether they hold up")

The user explicitly asked for an assessment of whether their two ideas make sense. Honest verdict:

### 2.1 Idea A — "an input for the game's path so the tool gives it special tracking"

**Verdict: the instinct is good, but the obvious mechanism ("watch the game's process") is of little
use. It needs to be reframed — and once reframed, it delivers real value.**

Why "watching `game.exe`" as a process does **not** work:
- The game itself **is not the threat**; the threat is the **Ring -1 hypervisor** and the fact that
  the crack **requires turning off HVCI/Secure Boot and loading an unsigned driver**.
- A Ring -1 hypervisor is, by design, **invisible from user space** (Ring 3). Monitoring the game's
  process from a user-mode app is theater: it will not see the hypervisor.

Why the **path/folder** is genuinely valuable (the reframe):
- The game folder is **exactly where the crack's components live** (the loader, `VBS.cmd`,
  the `.sys`, `elamigos` markers). The path is not a "process to follow" — it's a **scan target and
  a watch point**.
- Concrete, useful applications of that path:
  1. **Scanning the folder** with IOCs/YARA/hash/signature (reuses `pe-triage.py` + `denuvowo.yar`):
     finds the crack's known components alongside the game.
  2. **Folder ↔ posture correlation:** "this folder contains DenuvOwO components **and** your HVCI is
     off" = the compromised state, explained in one sentence.
  3. **Posture delta around the launch** (the genuinely valuable part): take a posture snapshot
     (T1) **before** the user launches the game, and **another one after**. If the act of launching
     the crack turned off HVCI or turned on `testsigning`, **we capture the exact moment** the
     defenses went down. This is what "tracking the game" really means: not following the process,
     but **watching what the launch does to the system's defenses**.
  4. **Watching the folder** (`FileSystemWatcher`): warn if new `.sys`/`.cmd` files appear (the crack
     updating itself).

**Honest limitation that must be disclosed:** we cannot detect the hypervisor **while it is running**
from user mode. Our leverage is (a) **before** it loads (if posture is still active, it cannot
load) and (b) the **side effects** it is forced to cause (protections turned off). This is
consistent with the project's thesis (`doc 04`): *the crack depends on you turning off HVCI; defend
that and you win.*

→ **Decision:** implement Idea A **reframed** as **Module M4** (§6.4): the path is a scan target +
posture correlation + launch delta + folder watch. **Do not** implement
game-process monitoring (low value, induces false confidence).

### 2.2 Idea B — "check whether the executable carries a malicious payload before installing/launching it"

**Verdict: partially possible and of HIGH value for a lay user, BUT it has a hard blind spot
that, if not disclosed, makes the feature dangerous (false security).**

What **can** be done reliably and defensibly (all static, without executing anything):
- **Hash + reputation:** SHA-256 of the target and comparison against (i) our list of known
  IOC hashes (`findings/hashes.csv`) and (ii) *optionally*, a **hash-only** query to
  VirusTotal (**opt-in**; a hash **is not** the file → there is no upload or exfiltration; even so,
  it's opt-in for privacy). It is the **highest-value signal** for a lay user.
- **Authenticode signature:** is it signed? is the chain valid? which publisher? A repacked crack
  loader is usually **unsigned** or has a signature that does not chain → red flag.
- **Static PE heuristics** (port the logic of `pe-triage.py`): *dropper* imports
  (network/injection/persistence), high entropy/*packer*, the presence of a `.sys` file or of
  driver-loading imports.
- **YARA** (`denuvowo.yar`) + **IOC name/structure scan** over the target folder.

**HARD blind spot (must be a headline in the UI):** the dangerous payload is **AES-256 encrypted
inside the FreeArc installer** and is **invisible until `setup.exe` runs** (see `HANDOFF.md` §4).
Therefore, a **pre-install** scan of `setup.exe` can only judge **the installer's shell**; a "clean"
result there **does NOT mean the crack is safe**. The scan that actually means something is **after
installing, on the already-extracted game folder, before the first launch** — which links
directly to Module M4.

**Second honest limitation:** this is a **known-threat detector + integrity checker**,
**not an antivirus**, and **not a guarantee**. Proving the *absence* of malware is, in general,
undecidable. We report **signals** and **integrity deviations**; we never say "it's safe" — we say
"I have not found known threats — this is not a guarantee."

→ **Decision:** implement Idea B as **Module M5** (§6.5), with two clearly labeled modes:
- **Pre-install (limited):** only the installer's shell; the UI prominently warns that it **cannot
  see the encrypted interior**.
- **Post-install / pre-launch (the useful one):** full scan of the already-extracted folder.

---

## 3. Architecture

### 3.1 Principle: immutable engine + thin orchestrating GUI

- **Engine = the already-validated `.ps1` files in `defense/`.** Their logic is not rewritten. The
  GUI invokes them as child processes and **reads their JSON output**. This preserves all the
  end-to-end validation already done and avoids reintroducing bugs.
- **Contract already in place (verified in the code):** the five scripts accept `-AsJson` and
  `-JsonPath <file>`, `-Quiet`, and return **standardized exit codes**:

  | Script | GUI action | Exit 0 | Exit 1 | Exit 2 |
  |---|---|---|---|---|
  | `T1-posture-check.ps1` | Check | `PASS` | `FAIL` | `INCONCLUSIVE` / not admin |
  | `T0-hv-detector.ps1` | Detect | `CLEAN` | `DETECTED` | `SUSPECTED` |
  | `T5-remediation.ps1` | Repair | healthy/remediated | pending / reboot required | errors |
  | `T2-hvci-enforce-monitor.ps1` | Harden+watch | compliant | change/drift | not admin/error |
  | `T3-wdac-block-unsigned-drivers.ps1` | Block drivers | ok | — | not admin/error |

  The GUI **never** parses console text: it launches with `-JsonPath "%TEMP%\hvguard\<t>.json"` and
  deserializes it. The JSON object already carries `overall`, checks with
  `Status/Observed/Expected/Evidence` → ready-made material for painting cards and the "why."

### 3.2 Elevation to Administrator

- The app **requires Administrator** (T2/T3/T5 demand it; T0/T1 read better with it).
- Mechanism: **manifest** `requestedExecutionLevel = requireAdministrator` → UAC on startup. If the
  user cancels the UAC prompt, the app starts in **read-only mode** (only M1 "Check"/"Detect") and
  shows a banner: "Restart as administrator to repair/harden."

### 3.3 New engine artifact to create: `defense/T7-target-scan.ps1`

Modules M4/M5 need a scanning engine. **Decision:** build it **in native PowerShell** (so as not to
depend on the end user having Python), reusing the *logic* of `pe-triage.py`:
- `Get-FileHash -Algorithm SHA256` → compare against `hashes.csv` (bundled) and (opt-in) VT hash-only.
- `Get-AuthenticodeSignature` → signature status + publisher.
- PE heuristics: read the header, sections, and import table (port of the `SUSPECT` lists from
  `pe-triage.py`: network/injection/persistence/driver) — or bundle a signed `yara64.exe` and run
  `denuvowo.yar`.
- Scan of **IOC names/structure** in the folder (`VBS.cmd`, `.sys`, `elamigos` markers).
- **`-AsJson`/`-JsonPath`** output and exit codes consistent with the rest (0 clean / 1 known threat /
  2 suspicious signals), so the GUI consumes it the same way as T0–T5.

> The executor of M4/M5 **first** builds and validates `T7-target-scan.ps1` as a console script
> (the same way it was done for T0–T5), and **only afterward** wires it into the GUI.

---

## 4. Technology stack (recommendation + alternatives)

**Recommended (v1): .NET Framework 4.8 + WPF (C#/XAML).**
- **Distribution advantage:** .NET Framework 4.8 is **preinstalled** on every Windows 10/11 machine →
  the end user **installs no runtime**. A single `.exe`.
- **Signable** with Authenticode (key to §8) → less SmartScreen/AV friction.
- The GUI **orchestrates** the engine with `Process.Start("powershell.exe", "-NoProfile
  -ExecutionPolicy Bypass -File Txx.ps1 -AsJson -JsonPath ...")`, captures the exit code, reads the
  JSON. The scripts are **bundled as resources** or in a signed subfolder.

**Fast alternative (prototype): PowerShell + WPF (XAML) packaged with PS2EXE.**
- **Advantage:** reuses the PS ecosystem directly, fast iteration.
- **Drawback:** PS2EXE binaries **trigger AV false positives** and are harder to sign cleanly.
  Acceptable for an internal demo; **not** ideal for community distribution.

→ **Decision:** prototype the UX in **PowerShell+WPF** if speed is the priority, but the
**distributable v1 is a signed .NET 4.8 WPF app**. In both cases the **engine remains the `.ps1`
files** — the logic is not reimplemented in C#.

---

## 5. UX design

### 5.1 Screen philosophy

A single window, "wizard" style, with a **big status light** and **verb buttons** (no acronyms).
No jargon up front; the technical details live behind a "View details."

### 5.2 Main screen (text wireframe)

```
┌───────────────────────────────────────────────────────────────┐
│  HVGuard — Protect your PC                        [?]  [≡]      │
├───────────────────────────────────────────────────────────────┤
│                                                                 │
│        ●  STATUS: PROTECTED / AT RISK / COMPROMISED             │
│        (green / amber / red status light, plain-language text)  │
│                                                                 │
│   "Your PC's protections are active."          [View details ▾] │
│                                                                 │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐      │
│   │  CHECK         │  │   REPAIR       │  │   HARDEN       │     │
│   │  (T1 + T0)     │  │   (T5)         │  │   (T2 + T3)    │     │
│   └───────────────┘  └───────────────┘  └───────────────┘      │
│                                                                 │
│   Game folder:  [ C:\Games\MyGame                  ] [Browse]   │
│   [ Scan this folder ]         [ Watch while playing (on/off) ] │
│                                                                 │
│   [status bar / last check / logs]                              │
└───────────────────────────────────────────────────────────────┘
```

### 5.3 Main flows

- **Check:** runs T1 + T0 in read-only mode → paints the status light. "PROTECTED" (T1 PASS and T0
  CLEAN), "AT RISK" (some protection is loose but no trace of the crack), "COMPROMISED" (T0
  DETECTED).
- **Repair:** runs `T5` first in **dry-run** → shows in plain language **what it would do** ("I'm
  going to re-enable Memory integrity and delete a suspicious registry key") → **"Apply"** button
  → `T5 -Apply`. If a reboot is required, it explains it ("A restart is needed to finish").
- **Harden:** `T2 -Enforce -InstallMonitor` (turns on protections + leaves the watcher running). `T3`
  starts in **`-Audit`** (never a silent enforce: blocking drivers badly can prevent the machine from
  booting; see §10).
- **Scan folder** (M4/M5) and **Watch while playing** (M4 launch delta): §6.

### 5.4 *Copy* rules (non-negotiable)

- Green = **"I have not found known threats,"** never "safe."
- Before any pre-install scan: banner **"I cannot see what is encrypted inside the installer until
  it is installed. Scan the game folder once it is installed, before you play."**
- No text encourages running the crack. The tool **assumes** the user makes their own decision and
  limits itself to **protecting them**.
- Every verdict offers a **"why?"** with the evidence from the JSON (which signal, observed value
  vs. expected) — traceability, just like in the scripts.

---

## 6. Functional specification by module

> M1–M3 are **UI wiring over an already-validated engine** (low risk). M4–M5 require the new
> `T7-target-scan.ps1` (§3.3). M6 is optional.

### 6.1 M1 — Status panel (wraps T1 + T0)
- "Check" button → runs both in read-only mode, combines them into one status light.
- "View details" expands the cards for each check with its evidence.
- **Acceptance:** on a healthy host it shows green; with HVCI off + `ManageVBS` created by hand it
  shows red and lists the reasons.

### 6.2 M2 — Repair (wraps T5)
- **Dry-run → plain-language preview → Apply** pattern. Translate each step R1–R8 into a sentence.
- Handle the "reboot/UEFI required" case with clear instructions.
- **Acceptance:** from a simulated compromised state, "Apply" re-enables HVCI and deletes
  `ManageVBS`; after rebooting, "Check" turns green.

### 6.3 M3 — Harden and watch (wraps T2 + T3)
- "Harden" → `T2 -Enforce -InstallMonitor`. Explain that a watcher will be left running that warns if
  something turns off the defenses (events 7000/7001 + `posture-log.jsonl`).
- `T3` **only in `-Audit`** from the GUI in v1. The jump to `-Enforce` **is not** exposed to the lay
  user (§10); it remains a documented advanced action.
- **Acceptance:** "Harden" leaves VBS/HVCI running and installs the `HVGuard-PostureMonitor` task; a
  triggered drift fires event 7001.

### 6.4 M4 — Game folder: scan + correlation + launch delta (**Idea A, reframed**)
- **Path input** (folder or `.exe`) with validation (exists, is accessible).
- **Scan this folder:** runs `T7-target-scan.ps1 <path>` → lists known crack components found
  (IOC/YARA/signature) and **correlates with posture** ("this folder carries DenuvOwO components
  and your HVCI is off → compromised state").
- **Watch while playing (launch delta):** when enabled, the app takes a **posture snapshot (T1)
  before**; the user launches the game **on their own** (the app **NEVER** launches it — CLAUDE.md
  §1); upon detecting that the process has ended, or via an "I've closed the game" button, it takes
  an **after snapshot** and **warns if the launch degraded the defenses**. Optional:
  `FileSystemWatcher` on the folder for new `.sys`/`.cmd` files.
- **Acceptance:** pointing at a folder with an IOC decoy file, it flags it; the posture delta
  detects an HVCI shutdown triggered by hand between the two snapshots.

### 6.5 M5 — Known-threat scanner (**Idea B, with explicit limits**)
- **Pre-install mode (limited):** on `setup.exe`/installer → shell only (hash, signature, PE
  heuristics on the shell). **Mandatory banner** about the blind spot (§5.4).
- **Post-install mode (the useful one):** on the already-extracted folder → full scan (same `T7`
  engine).
- **Hash reputation (opt-in):** checkbox "Check online reputation (only a hash is sent, never the
  file)". Off by default.
- **Result copy:** "I have not found known threats (this is not a guarantee)" / "⚠ I found signals
  you should review: …" / "⛔ Matches a known threat: …".
- **Acceptance:** an unsigned PE with injection imports → "signals to review"; a file whose hash is
  in `hashes.csv` → "known threat."

### 6.6 M6 — Telemetry (optional, wraps T4)
- Advanced button "Enable watch logging" → installs Sysmon with `sysmon-hv-bypass.xml`. Sigma rules
  only if there is a SIEM (outside the scope of the home user; document it). Low priority.

---

## 7. Guardrails the executor MAY NOT violate (from `CLAUDE.md`)

1. The app **NEVER** executes, installs, or launches anything from the sample: not `setup.exe`, not
   the game, not `VBS.cmd`, and it never loads drivers. In M4 "Watch while playing," **it is the
   user** who launches the game; the app only observes before/after.
2. The app **NEVER** disables protections (VBS/HVCI/Secure Boot/DSE) or turns on `testsigning`. Every
   action goes in the direction of **re-enabling/hardening**. (T5/T2 already comply with this; the
   GUI does not add buttons that violate it.)
3. **Nothing** about reconstructing/compiling/"fixing" the bypass. The M5 scanner **detects**; it does
   not repair or modify the crack's binaries.
4. **Do not** bundle download links for the crack, mirrors, or the source package in the
   repo/installer. IOCs/hashes by reference are fine.
5. **Do not** exfiltrate: the only permitted network output is the **opt-in, hash-only** query to VT;
   a file is never uploaded. No hidden telemetry.
6. `T3 -Enforce` (actual driver blocking) **is not** exposed to a lay user's click → risk of leaving
   the machine unable to boot (§10).
7. Whenever there is any doubt that touches on (a) executing the sample, (b) disabling a protection,
   or (c) producing something that amounts to a circumvention → **stop and ask**.

---

## 8. Packaging, signing, and distribution

- **A single `.exe`** with a `requireAdministrator` manifest. Engine scripts **signed** and included
  as resources or in a subfolder with signature verification at startup (prevents tampering with the
  engine).
- **Authenticode signature** on the `.exe` and on the `.ps1` files (ideally an EV cert to minimize
  SmartScreen). If there is no cert, document SmartScreen's "More info → Run anyway" flow in the user
  guide.
- **`ExecutionPolicy`:** the app calls PowerShell with `-ExecutionPolicy Bypass -File` over signed
  scripts; the user never touches policies.
- **Distribution:** outside the analysis repo. Publish as a separate *release* (binary + guide). **Do
  not** mix it with sample material.
- **AV false-positive prevention:** prefer a compiled + signed .NET 4.8 build over PS2EXE (§4).

---

## 9. Phased plan (tasks assignable to agents)

> Each phase ends with its **acceptance criteria** verified on a **disposable Windows VM with
> snapshots** (never against the sample). Incremental, auditable work.

- **Phase 0 — Scaffolding (1 agent).** GUI project structure (.NET 4.8 WPF), admin manifest, startup
  in read-only mode if UAC is canceled. *Acceptance:* the window opens, prompts for UAC, degrades to
  read-only if declined.
- **Phase 1 — Engine↔GUI bridge (1 agent).** A class that invokes a `.ps1` with `-JsonPath`, captures
  the exit code, and deserializes the JSON into a model. *Acceptance:* invokes T1 and displays its
  `overall` + checks.
- **Phase 2 — M1/M2/M3 (1-2 agents).** Wire up Check/Repair/Harden with the dry-run→apply pattern and
  the §5.4 *copy*. *Acceptance:* compromised→repair→green cycle reproduced from the GUI.
- **Phase 3 — `T7-target-scan.ps1` engine (1 agent).** Build and validate the scanner **as a console
  script** first (hash+signature+PE heuristics+YARA+folder IOC, `-AsJson`). *Acceptance:* detects the
  IOC decoy and known hash; produces no false positives on a cleanly signed PE.
- **Phase 4 — M4 (1 agent).** Path input, folder scan + posture correlation + launch delta
  (before/after) + optional watch. *Acceptance:* §6.4.
- **Phase 5 — M5 (1 agent).** Two modes (pre/post-install) with blind-spot banner and hash-only VT
  opt-in. *Acceptance:* §6.5.
- **Phase 6 — Packaging and signing (1 agent).** Signed `.exe`, plain-language user guide, *release*
  outside the repo. *Acceptance:* installs and runs on a clean VM with no extra dependencies.
- **Phase 7 (optional) — M6 telemetry.** Low priority.

Dependencies: F0→F1→F2 in series; F3 can run in parallel with F2; F4/F5 depend on F3; F6 at the end.

---

## 10. Risks and delicate decisions

- **`T3 -Enforce` can prevent booting** if it blocks a legitimate driver. **Decision:** in v1 the GUI
  only does `T3 -Audit`; the jump to enforce remains a documented advanced procedure, **after**
  reviewing event 3076. Do not expose it to a lay click.
- **False security (the biggest ethical risk):** mitigated by §5.4 and the blind-spot banners.
  Mandatory *copy* review before publishing.
- **Scanner false positives** damaging trust: calibrate `T7` to separate "known threat"
  (hash/IOC/YARA, high confidence) from "signals to review" (heuristics, lower confidence) and never
  mix them.
- **AV/SmartScreen false positives** on our own binary: sign it + prefer .NET over PS2EXE.
- **Cryptographic blind spot** (AES payload in FreeArc): acknowledged and disclosed; the scan that
  matters happens post-install.

---

## 11. User decisions (resolved 2026-07-13)

These four questions have already been decided by the user. They are **requirements**, not options:

1. **Online reputation — YES, opt-in and off by default.** M5 includes a checkbox the user
   voluntarily enables to check hash reputation (VirusTotal or equivalent). It sends **only the
   hash**, never the file or user data. Off by default. Without it, M5 works locally. Requires
   managing an API key (see Phase 5 / §6.5).
2. **Scope — internal use / close circle.** A paid EV certificate is not required: a standard
   Authenticode signature is enough (or document SmartScreen's "Run anyway" flow). Packaging
   (Phase 6) is simplified accordingly. *Note:* the rigor of the anti-false-security *copy* (§5.4)
   stays **exactly the same** — it is not relaxed for being internal.
3. **Name — "HVGuard"** (confirmed). Keep the brand in the UI, executable, and artifacts.
4. **Language — Spanish and English.** Bilingual UI: detect the system language with a manual
   selector. Externalize all text to localization resources starting in Phase 0 (do not *hardcode*
   strings).

---

## 12. Link to the current state

- Engine: `defense/T0–T5` **validated** (`HANDOFF.md` §5). This launcher is the missing layer for the
  **harm reduction** goal: bringing what has already been validated to the average user with no
  friction.
- New artifact for the executor to create: `defense/T7-target-scan.ps1` (§3.3), plus the GUI project.
- This document is **only the plan**. Implementation is carried out by other sessions/agents
  following §9.

---

## 13. Implementation status (updated 2026-07-13)

**IMPLEMENTED and validated** (read-only, real Windows; see `launcher/README.md` and
`launcher/TEST-RUNBOOK-WINDOWS.md`). Artifacts in `launcher/` + `defense/T7-target-scan.ps1`.

| Phase (§9) | Status | Note |
|---|---|---|
| F0 Scaffolding | ✅ | `HVGuard.ps1` (STA bootstrap + self-elevate + degrade to read-only), `Shell.xaml`, ES/EN i18n |
| F1 Engine↔GUI bridge | ✅ | `lib/Engine.ps1` `Invoke-HvgTool` → deserialized JSON; validated on pwsh 7 and WinPS 5.1 |
| F2 M1/M2/M3 | ✅ | Check (T1+T0→status light), Repair (T5 dry-run→Apply), Harden (T2 enforce+monitor, T3 **audit only**) |
| F3 `T7-target-scan.ps1` | ✅ | Console validated: hash-IOC + name-IOC → `KNOWN-THREAT`; unsigned `.sys` → `SUSPECT`; signed PE → `CLEAN` (no false positive) |
| F4 M4 Folder | ✅ | T7 scan + posture correlation + **launch delta** (never launches the game) + poll-based watch |
| F5 M5 Scanner | ✅ | Pre/post-install + blind-spot banner + opt-in hash reputation (off) |
| F6 Packaging/signing | ✅ .exe / ⏳ signature | **`dist/HVGuard.exe`** self-contained (C# stub + embedded ZIP, `tools/build-exe.ps1`, offline with Windows' own `csc`; no console, icon, asInvoker manifest). Validates `-SelfTest`. **Only the Authenticode signature is missing.** |
| F7 M6 Telemetry | ⏳ | Optional; not implemented (low priority) |

**Pending testing (only on a disposable VM with a snapshot; steps in runbook §3):** the full
*compromised → repair → green* cycle with real `T5 -Apply`, `T2 -Enforce`, `T3 -Audit`, and the
watcher's 7000/7001. Not tested on the real machine because of the guardrails (do not touch
protections).

**Deviations from the plan (justified):**
- **Stack = PowerShell + WPF** (the "fast alternative" from §4), not .NET 4.8. This is a **user
  requirement** (reuses the engine as-is, no compiler, self-elevates like the `.ps1` files do). The
  engine remains the `.ps1` files; the GUI only orchestrates.
- **UI built in code** in each module (not separate `.xaml` fragments) for robustness and to keep
  one file per module; `Engine.Import-HvgXaml` supports fragments if they were ever wanted.
- **Module text in ASCII** (no accents) for encoding safety on Windows PowerShell 5.1 (BOM-less
  files); the "chrome" (title/tabs/status light) does carry accents, via explicit UTF-8 loading.
- **Folder watch** with `DispatcherTimer` (polling on the UI thread) instead of `FileSystemWatcher`,
  to avoid the threading issues of .NET events in PowerShell+WPF.
- **Online reputation (VT)** implemented opt-in and **off by default**; it was not run live during
  testing (no API key; this respects the no-exfiltration rule).
- **`.exe` deliverable** (requested after the first delivery): instead of the .NET-WPF `.exe` from
  §4, a **C# launcher stub** was built, compiled with Windows' own `csc` (nothing installed), which
  **embeds and self-extracts** the `.ps1` files and launches the GUI. It does NOT reimplement the
  GUI/engine in C# → the principle "the engine is the validated `.ps1` files" is preserved. It is
  `asInvoker` to preserve `HVGuard.ps1`'s degrade-to-read-only behavior.
