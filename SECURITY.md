# Security Policy

## Why this matters here specifically

HVGuard runs as Administrator. To repair a weakened posture it edits Device Guard registry values,
Boot Configuration Data (BCD), Windows services, and can generate a Windows Defender Application
Control (WDAC) policy — all kernel-adjacent security controls. A bug that lets an unprivileged
process trigger one of those changes, redirect it to the wrong target, or feed it bad input is a
local privilege-escalation issue here, not a cosmetic one. Treat anything that runs elevated as
security-sensitive, in particular:

- Any path where `defense/T5-remediation.ps1` (repair), `T2-hvci-enforce-monitor.ps1` (enforce), or
  `T3-wdac-block-unsigned-drivers.ps1` (WDAC) could be made to act outside its intended target: an
  unvalidated path, a race between a check and the action it gates, an argument that reaches
  `bcdedit`/`sc.exe` without being sanitized.
- Anywhere the GUI (`launcher/`) could be tricked into calling one of those scripts with
  attacker-controlled parameters, or into presenting an Apply/Repair action as something other than
  what the user actually selected.
- The self-extracting `.exe` stub (`tools/exe/HVGuardLauncher.cs`): anything that would let it load
  or run something other than its own embedded, intact script tree.

## Reporting a vulnerability

Please report privately rather than opening a public issue: **<maintainer contact>**.

Include what you can: the affected script or module, your PowerShell version, and whether you were
running elevated or in read-only mode, plus the smallest reproduction you have. We will acknowledge
receipt and work with you on a fix before any public disclosure.

## Please do not attach samples

Do not attach crack binaries, ISOs, installers, or any part of a pirated game release to an issue, a
pull request, or a vulnerability report — including "just to reproduce the bug." This project does
not accept samples in any form. Describe the behavior in words, or reference a component by name and
SHA-256 the way `docs/02-iocs-and-load-chain.md` does. See `CLAUDE.md` for why.

## Signing status

Neither the `.exe` release nor the `.ps1`/`.cmd` sources are code-signed yet. Until they are, Windows
SmartScreen will warn on first run regardless of whether the build is legitimate. Verify the
published SHA-256 before trusting a download either way — do not treat "no warning" or "a warning"
as a substitute for checking the hash.
