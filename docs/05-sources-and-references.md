# 05 — Sources and references

Traceability for what is claimed in the package, and study material from **clean sources**.

> **Policy:** this repo does not include download links for the crack. Third-party research
> references (RE analyses) are listed for their **evidentiary value**; the download links that
> those repos may contain **must not** be followed. The study material comes from the
> **manufacturer** or from **reference open-source** projects, not from the integrated tool.

---

## 1. Provenance of the sample data (no URLs published)

- **Release listing** of the analyzed sample: an ElAmigos release of a 2026 Ubisoft Connect title,
  carrying the hypervisor bypass. Source of the data marked *[official]*: the loading procedure,
  the attribution to the "DenuvOwO team", and the `VBS.cmd`/F7 instructions. *Held by the analyst.
  Deliberately not linked, and release-catalogue details (version, size, language count) are
  omitted: they identify a download, not a threat.*
- **Third-party re-hosting mirror**: how the sample reached the analyst. It redistributes the
  ElAmigos release inside its own download wrapper, which is **unaudited** and therefore an
  independent risk; that wrapper was triaged separately in `findings/toolchain-triage.md`.
  *Deliberately not named.*

---

## 2. Technical press (context, timeline, countermeasures)

Establish: the general mechanics (Ring -1, CPUID spoofing, Denuvo intact but deceived), the timeline
(MKDev→DenuvOwO→Kirigiri), the need to disable low-level security, and that *the PC works but is left
without defenses*. Also Irdeto's response (countermeasures in the works).

- Tom's Hardware — *A brief history of Denuvo DRM and the new hypervisor bypass*
  `https://www.tomshardware.com/video-games/pc-gaming/a-brief-history-of-denuvo-drm-and-the-new-hypervisor-bypass-inside-the-cat-and-mouse-game-between-denuvo-and-the-piracy-scene`
- TweakTown — *Hypervisor-based bypasses defeat Denuvo with day-zero cracks…*
  `https://www.tweaktown.com/news/110787/hypervisor-based-bypasses-defeat-denuvo-with-day-zero-cracks-but-a-countermeasure-is-already-in-the-works/index.html`
- The FPS Review — *Denuvo Has Been Broken: Hypervisor Bypasses Enable Day-Zero Cracks…*
  `https://www.thefpsreview.com/2026/04/03/denuvo-has-been-broken-hypervisor-bypasses-enable-day-zero-cracks-irdeto-promises-a-fix/`
- GamerMarkt — *Denuvo Cracked: All PC Games Bypassed As DRM Falls In 2026*
  `https://www.gamermarkt.com/blog/denuvo-cracked-all-pc-games-bypassed-drm-2026/`
- Medium (Shlok) — *This new method of Piracy is breaking more than just DRMs*
  `https://medium.com/@shlokparab16517/this-new-method-of-piracy-is-breaking-more-than-just-drms-2a8787ee1e68`

---

## 3. Reverse-engineering analyses (basis for the data marked *[audit]*)

Establish: DenuvOwO's composition (includes `DenuoOwO_SRC.7z`; based on HyperDbg/SimpleSvm/EfiGuard),
the binary inventory, the techniques (CPUID/MSR spoofing, EPT hooks, LSTAR/EFER hooks), the
lifecycle/reversion (`VBS.cmd` option 3, `ManageVBS` key, DSE re-enabling on restart, hypervisor
unloading on close), the absence of general-purpose malware, and **the Ring -1 vulnerability**.

> Note: these are **static** analyses, some by independent/student authors who describe themselves
> as "unofficial"; they acknowledge that decompilation might not see obfuscated code. Treat as
> strong but not infallible evidence.

- 0xPacman — *RE-Reports / DenuvOwO_Hypervisor_Report.md* (DenuvOwO-specific analysis)
  `https://github.com/0xPacman/RE-Reports/blob/main/DenuvOwO_Hypervisor_Report.md`
- RD945 — *hypervisor-crack-audit* (MKDev/Kirigiri variant; list of open-source components)
  `https://github.com/RD945/hypervisor-crack-audit`
- haise0 — *kirigiri-hypervisor-crack-audit*
  `https://github.com/haise0/kirigiri-hypervisor-crack-audit`
- Sploitus — *Exploit for denuOwO-hypervisor-vulnerabilities* (vulnerabilities in DenuvOwO's Ring -1,
  `hyperhv.dll`, exploitable without admin)
  `https://sploitus.com/exploit?id=CAF30B94-3716-5ED0-9322-60CB8ECCE56D`
- Habr — *DENUVO Hypervisor. How does it work?* (technical scene write-up; detail on the CPUID check
  performed by the bypass DLL and why timing/CPUID checks are not a reliable solution)
  `https://habr.com/en/articles/1021894/`

---

## 4. Clean-source study material (understanding the primitives)

To understand VT-x/AMD-V, EPT, Blue Pill, and hooking **without touching the circumvention
artifact**. Reading the **upstreams** is also useful for the **stock-vs-custom diff** in `docs/03`
Phase D.

**Manufacturer specification**
- Intel® 64 and IA-32 Architectures Software Developer's Manual, **Vol. 3C** (VMX).
- AMD64 Architecture Programmer's Manual, **Vol. 2** (System Programming — SVM).

**Minimal reference hypervisors (open-source)**

> Licence note: this project **vendors none of the code below** — these are read and cited, never
> copied — so their terms place no obligation on this repository. Where a licence is named it is
> given as a courtesy to the author; the authoritative licence is always the one in the upstream
> repository, and that is what you should check before reusing any of it yourself.

- **SimpleSvm** (Satoshi Tanda) — basis of `SimpleSvm.sys`: `https://github.com/tandasat/SimpleSvm`
- **HyperPlatform** (Satoshi Tanda) — didactic Intel hypervisor with hooks:
  `https://github.com/tandasat/HyperPlatform`
- **SimpleVisor** (Alex Ionescu) — minimalist Intel hypervisor: `https://github.com/ionescu007/SimpleVisor`
- **HyperDbg** (Sina Karvandi) — **basis of DenuvOwO's VMM** (`hyperhv.dll`); reading it illuminates
  the original: `https://github.com/HyperDbg/HyperDbg`
- **EfiGuard** (Mattiwatti) — UEFI bootkit that disables PatchGuard/DSE; understand the boot
  variant **and** how to detect it: `https://github.com/Mattiwatti/EfiGuard`

**Canonical tutorial**
- *Hypervisor From Scratch* — Sina Karvandi (author of HyperDbg). Step-by-step series on building a
  research hypervisor from scratch (rayanfam / hvmi blog). Primary reference for the primitives.

**Defense / detection (for the axes in `docs/04`)**
- Documentation for **Windows Device Guard / HVCI / VBS**, **WDAC**, **Sysmon**, and the
  `Microsoft-Windows-CodeIntegrity/Operational` channel (events 3033/3077).
- **Sysinternals** (Autoruns, Process Explorer) for driver/startup inspection.

---

## 5. Legal note (Spain/EU context)

- The **circumvention of technological protection measures** and, in particular, the
  **manufacture, import, or provision of circumvention devices/services** are regulated by
  **arts. 160-162 of the TRLPI** (RDLeg 1/1996), the transposition of **art. 6 of Directive
  2001/29/EC**.
- The research exception is **narrow**; it is not equivalent to the broad reading sometimes given to
  the US §1201(g). That is why this project limits itself to **theory, static analysis, and
  open-source components**, and does **not** build or distribute the circumvention tool.
- Nothing here is legal advice. If in doubt about the scope of a specific activity, consult a
  professional.

---

## Citation convention used in the package

- *[official]* → ElAmigos release listing (§1).
- *[audit]* → RE analysis from §3.
- *[press]* → §2.
- Unmarked → virtualization theory / x86 architecture / our own defensive design.
