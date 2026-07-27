# HVGuard Glossary

This page explains, in plain English, the words and acronyms you might run into inside HVGuard.
If a game crack brought you here and one of its screens used a term you did not recognize, it is
almost certainly explained below.

## The five terms that actually matter

Everything else in this glossary is background. These five are the ones HVGuard actually puts on
screen, and the ones worth understanding properly.

### Memory integrity (HVCI)

Memory integrity puts a hard rule around the most sensitive part of Windows, the kernel: every
piece of code that wants to run there must carry a trusted digital signature, and the check is
made by a separate, isolated layer *outside* ordinary Windows, so nothing running inside Windows --
malware included -- can switch it off. Think of a bouncer on a locked door who cannot be bribed by
anyone already inside the building. This is the one protection the crack you ran cannot get around,
which makes it the single most important item on this page.

Where to see it: **Windows Security > Device security > Core isolation > Memory integrity**. Its
technical name, which you may see in other write-ups, is Hypervisor-enforced Code Integrity -- HVCI.

### Virtualization-based security (VBS)

VBS is Windows starting its own small, extra hypervisor at boot and using it to wall off a chunk of
memory that ordinary Windows cannot reach into. Memory integrity (above) is one of the protections
that lives inside that walled-off area; without VBS running, Memory integrity has nowhere to run and
cannot do its job.

Where to see it: open **System Information** (search the Start menu for `msinfo32`) and check
whether "Virtualization-based security" is reported as Running.

### Secure Boot

Secure Boot is a check your PC's firmware performs before Windows even starts, allowing only
startup software signed by a trusted key to run -- it stops something from planting itself ahead of
Windows in the boot order. It lives in firmware, not in Windows: Windows can only read whether it is
on, never switch it, which is why HVGuard cannot turn it on for you even with your permission.
Turning it on is a manual step in your PC's BIOS/UEFI menu.

Where to check its state: **System Information** (`msinfo32`) reports the current Secure Boot
state. Important: Memory integrity does not need Secure Boot to work, so you can be protected
against this specific bypass even while Secure Boot stays off.

### Driver signing (Driver Signature Enforcement, DSE)

Windows normally refuses to load a driver -- a small, powerful piece of software that runs inside
the kernel, with the same authority as Windows itself -- unless it carries a valid signature from a
certificate Windows trusts. This rule is called Driver Signature Enforcement, or DSE. The crack
relaxes it one of two ways: a one-boot-only override at startup (pressing F7 when Windows' boot
menu offers it), or a persistent developer setting called test-signing mode, which makes Windows
also accept drivers signed with untrusted test certificates.

There is no settings page for test-signing. The only visible sign it is switched on is a **"Test
Mode" watermark** Windows stamps onto your desktop. If you have seen that watermark, this is what
it means.

### Unsigned driver

A driver with no valid signature at all, or one whose signature does not check out. Under normal
settings Windows will not load one, because a driver runs with the same authority as Windows itself
-- getting one loaded anyway is most of what this crack is actually for. Driver signing (above) is
the front door for this; Memory integrity (above) is the door that stays locked even if the front
door was forced.

## Everything else, A-Z

The five terms above (Memory integrity/HVCI, VBS, Secure Boot, Driver signing/DSE, Unsigned driver)
are not repeated below. Everything else you might see in HVGuard, its tools, or its documentation,
in one line each.

| Term | In plain words | Why it appears in HVGuard |
|---|---|---|
| Allowlist | A list of things explicitly permitted; anything not on it is left untouched. | HVGuard's repair step only ever quarantines or deletes a driver or file whose exact name is on a small, fixed allowlist of known crack components -- never a guess. |
| API | A defined way for one piece of software to ask another to do something. | HVGuard's scripts use Windows' own documented APIs to read your settings, instead of guessing from side effects. |
| Authenticode | Microsoft's system for digitally signing a program so Windows can verify who published it and that it has not been altered. | HVGuard checks whether a driver carries a valid Authenticode signature; the crack's own driver is expected to have none. |
| Baseline | A saved snapshot of your protections at one point in time, kept for later comparison. | The "Game folder" module takes a baseline snapshot before you play and compares it to one taken after, to see whether anything weakened your defenses in between. |
| BCD / bcdedit | BCD (Boot Configuration Data) is the settings store Windows reads at startup, before the full OS loads; `bcdedit` is the built-in tool used to read or change it. | Two of the settings the crack changes -- test-signing and whether Windows' own hypervisor starts -- live in the BCD; HVGuard's repair resets them with the same tool. |
| BIOS / UEFI / firmware | The low-level software built into your motherboard that runs before Windows starts and hands control over to it; UEFI is the modern replacement for the old BIOS. | Secure Boot and your CPU's virtualization switch both live here, not in Windows, which is why some fixes need a trip into this menu instead of a Windows setting. |
| Blocklist | The opposite of an allowlist: a list of things specifically refused, with everything else allowed by default. | See "Vulnerable driver blocklist" below for the specific one Windows maintains. |
| Boot chain / bootkit | The boot chain is the sequence -- firmware, then boot loader, then Windows -- that Secure Boot tries to verify step by step; a bootkit is malware that inserts itself into that sequence, ahead of Windows. | A sibling of this crack family uses a bootkit (EfiGuard) instead of a driver; HVGuard's Secure Boot checks exist partly to catch that variant too. |
| BYOVD | Short for "bring your own vulnerable driver": loading an old, legitimately-signed driver with a known bug, and abusing the bug, instead of writing new malicious code. | It is the attack the "vulnerable driver blocklist" (below) defends against -- a relative of this bypass, not the exact technique it uses. |
| CLI / GUI / PS | CLI: a command-line interface, where you type commands. GUI: a graphical interface, where you click things. PS: PowerShell, the scripting language HVGuard is written in. | HVGuard is a GUI wrapped around a set of PS command-line tools, so you never have to type a command yourself. |
| Code Integrity | The part of Windows that checks a piece of code's signature before letting it run, especially inside the kernel. | Memory integrity (HVCI) is Code Integrity enforced from outside Windows by the hypervisor, so it cannot be switched off from inside. |
| CSM | An older BIOS compatibility mode for booting non-UEFI systems. | Mentioned only for completeness: it usually has to be off before Secure Boot is even an option in your firmware menu. |
| CSV / JSON / JSONL / XML | Plain-text formats for storing structured data -- CSV is spreadsheet-style rows; the others are formats programs use to save records. | HVGuard's scan results and findings can be exported in these formats for your own records. |
| DBX | The "revoked signatures" list Secure Boot checks against -- the opposite of the list of trusted signers. | Background to Secure Boot, included for completeness; HVGuard does not read it directly. |
| Delta | The difference between two measurements. | The "Game folder" module reports the delta between your before and after baselines, so you see only what changed. |
| DenuvOwO | The name of the specific crack family HVGuard was built to detect and clean up after. | It is the reason this tool exists; HVGuard never distributes it and will not run it. |
| DMA | Direct Memory Access -- a way hardware devices can read or write memory directly. "DMA protection" is a VBS feature that restricts this to trusted devices. | One of the security properties VBS can require; HVGuard's repair may need to adjust which properties VBS requires if your hardware cannot offer all of them. |
| DSE | Short for Driver Signature Enforcement; see "Driver signing" above. | Included here so the acronym is findable on its own. |
| Dry run | Showing what an action would do, in detail, without actually doing it. | Every HVGuard repair step previews itself as a dry run first; nothing changes until you explicitly choose to apply it. |
| Entropy | A measure of how random-looking a chunk of data is; packed or encrypted code tends to score high. | Used during the analysis that built HVGuard's detection signatures, to help tell disguised code apart from ordinary code. |
| Event Viewer | The built-in Windows app for browsing logs of what the system and its programs have done. | HVGuard's posture monitor and Windows itself record entries there; it is a normal Windows tool, not something the crack installs. |
| Guest / host | In virtualization, the "host" is the real machine (or the hypervisor's own view of it); a "guest" is an operating system running inside a virtual machine (VM), under a hypervisor's control, unaware it does not have the whole machine to itself. | This bypass's driver "hot-virtualizes" the copy of Windows you are already running, without a restart, turning your live session into a guest underneath its own tiny hypervisor. |
| Hash | A short fingerprint calculated from a file's contents (HVGuard uses SHA-256); changing even one bit of the file changes the hash completely. | Used to recognize known crack components and to build detection lists, without needing to run or even fully open the file. |
| Heuristic | A rule-of-thumb pattern match, used when there is no exact hash or name to compare against. | HVGuard's scanner combines hash, name, signature and heuristic checks; a heuristic hit means "this looks like it," not a certainty. |
| HVGuard-BlockUnsignedDrivers | The name HVGuard gives the WDAC policy it can build for you. | You may see this name in Windows if you generate the policy; it is HVGuard's own label, not something the crack created. |
| HVGuard-PostureMonitor | The name of a Windows Scheduled Task HVGuard can create to re-check your protections periodically. | You may see this name in Task Scheduler or Event Viewer; it is HVGuard's own watcher, not something to be alarmed by. |
| hyperkd.sys / hyperhv.dll / hyperevade.dll | Three components of the crack's own hypervisor: a support kernel driver, the core virtualization engine, and an anti-detection layer. | Named specifically so detection lists (and this glossary) agree on what each file is; hyperhv.dll is the one with its own publicly documented Ring -1 bugs. |
| Hypervisor / virtualization | Software that runs underneath an operating system and can control what that operating system sees and does. HVGuard's own file and script names often shorten "hypervisor" to "HV". | Both Windows' own defense (VBS) and the crack's bypass are hypervisors; HVGuard's detector specifically checks for one running where it should not be. |
| hypervisorlaunchtype | A boot switch that controls whether Windows' own hypervisor starts at all. | Needed, alongside VBS and Memory integrity, for those protections to actually run; HVGuard's repair resets it to the normal value. |
| IOC / IOCs | Indicator of Compromise: a specific, concrete sign (a file name, a hash, a registry key) that something was present or active. | HVGuard's checks and detector are built almost entirely from a list of IOCs specific to this crack family. |
| Kernel | The core of Windows that has full control of the machine -- memory, hardware, every other process. | The entire point of this bypass is getting unsigned code to run at kernel level; every protection on this page exists to stop exactly that. |
| KPP | Kernel Patch Protection -- another name for PatchGuard, below. | Included so the acronym is findable on its own. |
| ManageVBS | A registry key the crack's own script creates, so it can remember which protections it turned off and reverse them later. | Its presence is a direct sign the technique was prepared or used on this PC; HVGuard's repair deletes it once the real protections are restored. |
| MBEC | Mode-Based Execution Control -- a CPU feature that helps a hypervisor enforce stricter rules about what memory may run as code. | One of several hardware features that make Memory integrity stronger when present; HVGuard does not require it to check whether Memory integrity is on. |
| nointegritychecks | A boot switch that tells Windows to skip driver signature checks entirely -- a blunter version of test-signing. | The other of the two ways an unsigned driver can get into the kernel; HVGuard's repair turns it back off. |
| PatchGuard (KPP) | A Windows mechanism that watches for unauthorized changes to core kernel structures. | Some variants of this crack family try to work around PatchGuard; mentioned here mainly to distinguish it from Memory integrity, which is a different protection. |
| PCR / PCR 7 | A Platform Configuration Register: a slot inside the TPM chip that stores a cryptographic measurement of one specific stage of startup. PCR 7 specifically measures Secure Boot's state. | Explains why turning Secure Boot on or off can make BitLocker suddenly ask for its recovery key: PCR 7 changed, so BitLocker no longer recognizes the boot state it trusted. |
| PE header | The "PE" (Portable Executable) header is the label at the start of a Windows program (.exe/.sys/.dll) describing its structure, before any of its code runs. | HVGuard's analysis tools read the PE header to identify and triage files without ever executing them. |
| Platform Key | The top-level cryptographic key for Secure Boot, normally owned by your PC's manufacturer. | Whoever holds it controls what Secure Boot trusts; mentioned here as background to the Secure Boot entry above. |
| Posture | The overall state of your protections at a given moment -- on or off, present or absent. | HVGuard's "Check" module measures your posture and reports a single PROTECTED / AT RISK / COMPROMISED verdict from it. |
| ProgramData / LOCALAPPDATA | Standard, mostly-hidden Windows folders where installed programs and your own apps store settings and working files. | Both HVGuard's own monitor and the crack's leftover files can live in folders like these; seeing the path is not, by itself, a sign of anything wrong. |
| Quarantine | Disabling something without deleting it, so the action can still be undone. | HVGuard's default way of dealing with a leftover crack driver: mark it not to start, but leave the file alone. |
| Registry | A structured database Windows and its programs use to store settings. | Several of the settings this bypass changes, and several of HVGuard's own repairs, are registry values; seeing "registry" in a technical detail is normal, not alarming. |
| Remediation | The general term for fixing a problem that was found -- HVGuard calls this "Repair" in plain English. | Everything HVGuard's remediation does moves in the direction of restoring a protection; none of it disables one. |
| RequirePlatformSecurityFeatures | A registry setting that can make VBS refuse to start unless Secure Boot is also on. | If your Secure Boot is off, HVGuard's repair removes this specific requirement so Memory integrity can still run -- it does not touch Secure Boot itself. |
| Ring -1 | A privilege level below the normal kernel, where a hypervisor runs -- able to observe and control the kernel without the kernel's permission. | Where the crack's own hypervisor operates once it has loaded; the level Windows' own defensive hypervisor also operates at, on the defending side. |
| Ring 0 | The privilege level the Windows kernel and its drivers normally run at -- full control of the machine, but still visible to anything running at Ring -1. | Contrasted with Ring -1 above; it is why a hypervisor below the kernel can see and do things ordinary kernel code cannot prevent. |
| Scheduled task | A Windows feature for running something automatically, on a timer or trigger, without you starting it by hand. | HVGuard-PostureMonitor (above) is a scheduled task; Task Scheduler is where you would find or remove it. |
| SetupMode | A UEFI state meaning no Platform Key has been enrolled yet -- Secure Boot's trust list is effectively unlocked. | Background to the Secure Boot entry above; not something HVGuard's repair can change, since it lives entirely in firmware. |
| Sigma | A shared, vendor-neutral format for writing detection rules against logs and events, as opposed to files. | HVGuard's project includes Sigma rules a security team could load into their own monitoring system to watch for this bypass. |
| SimpleSvm | An open-source, educational AMD hypervisor project. The crack's own kernel driver is built on top of it. | Naming the upstream project lets HVGuard (and anyone else) tell the crack's custom code apart from the unmodified open-source base it started from. |
| SMM | System Management Mode -- a special, highly privileged CPU mode used by firmware, above even the kernel. | Standard PC hardware background, included for completeness; not something HVGuard's checks report on directly. |
| STA / MTA | Single- and Multi-Threaded Apartment -- internal plumbing terms for how a Windows program's threads talk to certain components. | Purely an engineering detail of how HVGuard's own window is built; it has nothing to do with your security settings. |
| SVM / VMX | AMD calls its CPU virtualization feature SVM (Secure Virtual Machine); Intel's equivalent is VMX (Virtual Machine Extensions), often marketed as VT-x. | Both Windows' VBS and the crack's own hypervisor rely on one of these, depending on your CPU brand; HVGuard's checks work the same way either way. |
| Sysmon | A free Microsoft tool that logs detailed system activity, like driver loads, beyond what Windows records by default. | HVGuard's project includes Sysmon-based detection rules; Sysmon itself is not part of HVGuard and is not required to use it. |
| Telemetry | Automatically recorded data about what a system is doing, kept for later review. | Refers to Windows' own logs (Event Viewer, Sysmon) that HVGuard's rules watch, not data HVGuard sends anywhere. |
| Testsigning / test-signing / Test Mode | See "Driver signing" above. | Included here so the term is findable on its own. |
| TPM | Trusted Platform Module -- a small security chip (or firmware equivalent) that stores encryption keys and boot measurements. | PCR 7, mentioned above, is a slot inside the TPM; background to Secure Boot, not something HVGuard reads directly. |
| UAC | User Account Control -- the "Do you want to allow this app to make changes to your device?" prompt. | HVGuard needs administrator rights to apply any repair; this is the prompt you will see when it asks. |
| VT | VirusTotal -- a third-party online service that checks a file's hash against many antivirus engines' opinions. | HVGuard's scanner has an opt-in checkbox to check a hash against VT; it is off by default, and even switched on it sends only the hash, never your file. |
| VTL1 | Virtual Trust Level 1 -- the isolated memory zone VBS creates, where Memory integrity's checks actually run. | The "walled-off area" described in the VBS entry above, by its technical name. |
| Vulnerable driver blocklist | A list Microsoft maintains of legitimate drivers with known bugs, refused from loading regardless of their valid signature. | Defends against BYOVD (above). Its toggle sits on the same page as Memory integrity: Windows Security > Device security > Core isolation. |
| WDAC | Windows Defender Application Control -- lets a PC's owner define exactly which drivers and apps are trusted to run. | HVGuard's "Harden" step can build a WDAC policy that blocks unsigned drivers like the crack's; by default it only audits (reports) rather than blocks, since blocking can be strict enough to affect booting. |
| WMI | Windows Management Instrumentation -- a standard, documented way for a program to ask Windows questions about its own state. | HVGuard's scripts use WMI (through its modern interface, CIM) to read things like VBS status, instead of guessing from side effects. |
| YARA | A pattern-matching language for scanning files for known malicious or suspicious content. | HVGuard's scanner uses YARA rules built from this crack's own code and strings; it always scans files, never live memory. |

## Words we deliberately avoid

HVGuard's short labels -- tab names, button text, status words -- contain no jargon and no bare
acronyms at all: the tabs are called "Check," "Repair," "Harden," "Game folder," and "Scanner," not
"HVCI Enforcement Console." That is a deliberate rule the project holds itself to, not an accident.

In the longer explanations, an acronym is never dropped on you without warning. The first time one
appears, it is introduced next to its plain-English name -- "Memory Integrity (HVCI)",
"Virtualization-Based Security (VBS)" -- so you can match a more technical write-up you may have
already read (a forum post, a security vendor's advisory) back onto what HVGuard is telling you. If
you came here from one of those, this glossary is the bridge: look the acronym up above, then read
HVGuard's screen with the plain name in mind.

One more thing you will not find HVGuard saying: that any of this makes your PC "safe." Its own
status light spells this out on purpose -- green means "no known threats found," never "it is
safe." That distinction is intentional, and it applies to this glossary too.
