# 01 — Technical dossier: the hypervisor-based bypass technique

Reference document on **how the system works**. First the systems theory (neutral, OS internals);
then the specifics of the **DenuvOwO** component that accompanies the sample.

> Traceability convention: *[audit]* = public third-party RE report; *[official]* = ElAmigos release
> listing; unmarked = virtualization / architecture theory. URLs are in
> `docs/05-sources-and-references.md`.

---

## 1. Context: why this technique exists

Denuvo (by Irdeto) is an anti-tamper/DRM whose commercial value is **delaying** the appearance of
copies during the launch window. Classic cracking required **reverse-engineering the DRM code paths
over months**. The hypervisor technique changes the approach: instead of touching the executable
(what the anti-tamper detects), it **operates below the OS** and deceives Denuvo from there.

**Established timeline:**
- Late 2025: PoC by the **MKDev** collective on *Persona 5 Royal*. *[audit/press]*
- Refinement by **DenuvOwO**. *[audit/press]*
- Applied at scale by crackers such as **Kirigiri**: *Resident Evil: Requiem* bypassed ~1 hour after
  its release (Feb. 2026), simultaneously defeating Denuvo + Steam DRM + Capcom Anti-Tamper + VMProtect +
  SteamStub. *[press]*
- By April 2026, essentially all single-player games with Denuvo had been bypassed. *[press]*

Key distinction: **this is not a "crack" in the traditional sense**. Denuvo's code **remains
intact** inside the game; it is **tricked into not acting**. *[press]*

---

## 2. Virtualization fundamentals (neutral)

### 2.1 Rings and Ring -1
The x86 protection model places the OS kernel at **Ring 0** and the user at Ring 3. Hardware
virtualization introduces a level **below the kernel**, colloquially **Ring -1**, where a
**hypervisor** runs. Whoever controls Ring -1 has more visibility and control than the OS itself, and
sits **below the antivirus** (which runs at Ring 0).

### 2.2 Hardware extensions: VT-x / AMD-V
- **Intel VT-x (VMX):** `VMXON`, `VMLAUNCH`, `VMRESUME` instructions; `VMCS` control structure.
- **AMD-V (SVM):** AMD's equivalent; `VMCB` structure.
They allow creating a **guest** context and defining which guest events trigger a **VM-exit** (a
"trap" that returns control to the hypervisor).

### 2.3 "Blue Pill" — virtualizing an OS that is already running
Concept by Joanna Rutkowska (2006): a **thin** hypervisor can **hot-virtualize the OS that is already
running**, turning it into a *guest* **without the OS knowing**. It does not boot a new VM: it
"wraps" Windows from below. This is the base primitive of the technique.

### 2.4 Instructions that can be intercepted
- **`CPUID`** unconditionally triggers a VM-exit → the hypervisor **intercepts every CPUID** and can
  **rewrite** what the guest sees. This is the central lever of the spoofing.
- **MSRs**: hooking `LSTAR` (syscall entry point) and `EFER` to intercept the syscall flow.
- **EPT/NPT** (Extended/Nested Page Tables): second-level address translation. Enables
  **split-view hooks**: the same address returning **different bytes on read versus on
  execution**.

---

## 3. How the hypervisor defeats Denuvo

Denuvo **fingerprints** the machine (via `CPUID`, MSRs, and others) to derive a **token** tied to the
licensed hardware, plus *anti-tamper* integrity checks. The bypass:

1. **CPUID/MSR spoofing:** the hypervisor returns the hardware values **for which a valid token was
   generated**, so Denuvo's checks pass. It also **hides its own presence** from Denuvo's VM
   detection. *[audit]*
2. **EPT hooks (invisible patching):** Denuvo **reads clean bytes** but the CPU **executes patched
   bytes**. This neutralizes checks without the integrity verifications "seeing" the patch. *[audit]*
3. **Syscall interception (LSTAR/EFER):** captures the **license validation** calls.
   *[audit]*

Result: Denuvo "believes" it is on the legitimate machine and lets the game run, with its code intact.

> Anti-cat-and-mouse note (technical scene source): one obvious check Denuvo could make is to look at
> the hypervisor interface signature via CPUID, but starting to check every CPUID value only leads to
> another escalation of checks/spoofs; *timing*-based checks are considered unreliable. This explains
> why the technique is difficult to counter **from inside the game** — and why effective defense is
> **platform-level** (HVCI), not application-level.

---

## 4. Why system security has to be disabled

Loading a third-party hypervisor on Windows requires **loading an unsigned kernel driver** and
**operating below the kernel**. Windows blocks this with several layers, and **all** of them must
fall for the technique to work:

| Protection | What it does | Why it gets in the technique's way |
|---|---|---|
| **Secure Boot** | Verifies the signed boot chain | Would reject the unsigned boot component. **Must be OFF** (unless one holds the Platform Key). *[audit]* |
| **DSE** (Driver Signature Enforcement) | Requires signed kernel drivers | Blocks `SimpleSvm.sys`/`hyperkd.sys` (unsigned). Disabled via *test signing* or via the boot menu (F7). |
| **PatchGuard** (KPP) | Prevents patching kernel structures | The variant with **EfiGuard** neutralizes it; the Ring -1 hypervisor also evades its reach. *[audit]* |
| **VBS / HVCI** | Hypervisor-enforced code integrity (VTL1) | **The technique CANNOT bypass it.** This is the real countermeasure. *[audit]* |

**Security consequence (independent of whether the crack is malicious):** during execution the system
is left with **kernel defenses down**. As the technical press sums it up: *the PC works, but it's left
without defenses*. Any subsequent malware would operate at the kernel level unopposed. *[press]*

---

## 5. The specific component: DenuvOwO

The sample's official listing states: *"Release is using Hypervisor bypass by **DenuvOwO** team"*. *[official]*

### 5.1 Composition (open-source + custom)
- **Includes its own source code:** `DenuoOwO_SRC.7z`. *[audit]* → **it can be read, no need to
  blind-decompile**.
- Built on **open** research projects: *[audit]*
  - **HyperDbg** — full open-source Intel VT-x hypervisor (EPT, VMCS, debugging); basis of the
    **VMM** (`hyperhv.dll`).
  - **SimpleSvm** (MIT, Satoshi Tanda) — minimal educational hypervisor for **AMD SVM**; turns the
    running OS into a *guest* while it runs at Ring -1 (`SimpleSvm.sys`).
  - **EfiGuard** (GPL-3.0) — disables PatchGuard/DSE in the **boot variant**.

### 5.2 Binaries/artifacts observed in the package *[audit]*
`hypervisor-launcher.exe`, `SimpleSvm.sys`, `hyperkd.sys`, `hyperhv.dll`, `hyperevade.dll`, `VBS.cmd`,
`DenuvOwO.nfo` (plus `_Info.txt` per the official listing). Detail and interpretation in `docs/02`.

### 5.3 Implemented techniques *[audit]*
- Full **AMD SVM** and **Intel VT-x** hypervisors.
- **Transparent CPUID and MSR spoofing** to hide from Denuvo's VM detection.
- **EPT-based memory hooks** (Denuvo reads clean, executes patched).
- **Syscall interception via LSTAR/EFER hooks** for the license validation calls.

### 5.4 Lifecycle and reversion *[audit]*
- `VBS.cmd` **option 3** restores **all** security settings using the tracking key
  `HKLM\SOFTWARE\ManageVBS`.
- **DSE re-enables itself after a restart** (the F7 method disables signing **only for that boot**).
- The **hypervisor unloads as soon as the game closes** (`ProcessExitCleanup` → stops the spoofing
  thread, **de-virtualizes the cores**, restores `KUSER_SHARED_DATA`).
- **Not persistent malware.** *(Caveat: protections disabled manually, if the EfiGuard variant was
  used, remain off until re-enabled or a clean boot is performed.)*

---

## 6. Risk verdict (nuanced)

Two questions that **must not** be conflated:

1. **Is it malware?** Multiple independent audits + the included source code agree that **there are
   no malicious payloads** (no C2, no exfiltration, no mining/botnet). *Honest caveat from the
   analysts themselves:* these are **static** analyses by independent/student projects, "unofficial",
   and **decompilation might not see obfuscated code**. *[audit]*
2. **Is it dangerous?** **Yes**, for reasons that do not depend on malicious intent:
   - To load it you **tear down kernel defenses** (DSE/PatchGuard/Secure Boot; VBS off).
   - It has been documented that **DenuvOwO's own Ring -1 code (`hyperhv.dll`) has critical
     vulnerabilities exploitable from any process without admin rights** → a **privilege escalation**
     surface while it is loaded. *[audit]*
   - Buggy kernel drivers can cause **BSODs**; MKDEV warns that **long-term stability is unproven**.
     *[audit]*
   - The **redistribution layer** (a third-party re-hosting mirror, in the analyzed case) is an
  **unaudited wrapper**.

**Operational translation for defense:** the goal is not to "hunt for a trojan". It is (a)
**preventing the technique from taking hold** (HVCI + Secure Boot + blocking unsigned drivers), (b)
**detecting** the hypervisor and state changes, and (c) **repairing** the settings that were brought
down. See `docs/04`.
