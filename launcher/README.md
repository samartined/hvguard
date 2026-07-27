# HVGuard — launcher (PowerShell + WPF GUI)

A bilingual (ES/EN) desktop interface for **non-technical** users that **wraps** the already-validated
defensive suite (`../defense/T0..T5` + the new `T7`). It **does not reimplement** its logic: it launches
each `.ps1` as a child process with `-AsJson -JsonPath` and **consumes its JSON**. 100% defensive.

> Guiding principle — **never give false security**: green means *"no known threats found"*, never
> *"it is safe"*. No text encourages running the crack; in "Watch while you play" it is the **user** who
> launches the game, HVGuard only observes before/after.

## How it runs

- **Double-click `dist\HVGuard.exe`** — a single self-contained file. The first time, it
  self-extracts to `%LOCALAPPDATA%\HVGuard\<build>\` and starts the GUI (later launches reuse that
  extraction). **Recommended way to share it.**
- For development, also: **double-click `HVGuard.cmd`**, or:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\HVGuard.ps1
  # or, if you have PowerShell 7:
  pwsh -NoProfile -STA -File .\HVGuard.ps1
  ```
- On startup it **self-elevates** (UAC). If you cancel the UAC prompt → **read-only mode** (only *Check*
  and *Analyze*; *Repair*/*Harden* are disabled with a warning).
- Compatible with both **Windows PowerShell 5.1** and **PowerShell 7**. WPF requires **STA**; the
  bootstrap automatically re-launches itself in STA if needed (PS7 starts in MTA).

## Packaging (.exe)

`dist\HVGuard.exe` is a **launcher stub** (C#, ~100 KB, compiled with the `csc.exe` that ships with the
.NET Framework already on Windows — **no install, no internet needed**) that **embeds** the whole
script tree as a ZIP resource, self-extracts it and starts `HVGuard.ps1`. It **does not reimplement**
any logic: the engine and GUI are still the `.ps1` files. The `.exe` is `asInvoker` on purpose →
elevation (and the fallback to read-only if UAC is cancelled) is still handled by `HVGuard.ps1`.

Rebuild it after changing any `.ps1`/`.xaml` file:
```powershell
pwsh -NoProfile -File tools\build-exe.ps1      # -> dist\HVGuard.exe
# unattended validation:
dist\HVGuard.exe -SelfTest -SelfTestMs 1500     # writes %TEMP%\hvguard-selftest.out
```
Stub and icon source in `tools/exe/` (`HVGuardLauncher.cs`, `app.manifest`, `hvguard.ico`).

## Structure

```
launcher/
  HVGuard.ps1              bootstrap: STA + self-elevation + i18n + loads XAML + discovers/starts modules
  HVGuard.cmd             double-click launcher
  lib/
    Engine.ps1            engine<->GUI bridge: Invoke-HvgTool (launches defense\*.ps1, deserializes JSON), Import-HvgXaml
    UI.ps1               WPF helpers: status light, evidence cards, UI refresh
    Shell.xaml             window (no x:Class or inline events; loadable via XamlReader)
    i18n/es.psd1, en.psd1  "chrome" text (title, tabs, status light)
    Modules/
      M1-status.ps1      Check       (T1 + T0 -> status light PROTECTED/AT RISK/COMPROMISED)
      M2-repair.ps1      Repair      (T5: dry-run -> Apply)
      M3-harden.ps1      Harden      (T2 -Enforce -InstallMonitor; T3 -Audit ONLY)
      M4-folder.ps1      Game folder (T7 + posture correlation + launch delta + watch)
      M5-scanner.ps1     Scanner     (T7: pre/post-install + opt-in hash-based reputation)
  TEST-RUNBOOK-WINDOWS.md step-by-step test guide
```

## Engine<->GUI contract

`Invoke-HvgTool -ScriptName <T0|T1|T2|T3|T5|T7> [-Params @{...}] [-TimeoutSec n]` returns
`@{ Ok; ExitCode; Result(deserialized JSON); Raw; StdErr; TimedOut; Error }`. The GUI **never** parses
console text. For actions that change state (T5 `-Apply`, T2 `-Enforce`, T3 `-Audit`) `Force=$true` is
also passed (the scripts use `ShouldProcess`; without `-Force` they would prompt for interactive
confirmation in a process with no console).

Each module defines `Initialize-HvgModule_<Name>($Ctx)`, touches **only its own Grid**, wires up events
in code, and respects `$Ctx.ReadOnly`. Each module's own text lives inside the module (ASCII, for
encoding robustness on 5.1; the "chrome" with accented characters loads via explicit UTF-8).

## Scope / signing

Internal use / inner circle → standard Authenticode signing (no EV cert). Neither `dist\HVGuard.exe`
nor the `.ps1`/`.cmd` files are signed in the repo. To distribute, sign the `.exe` and document
SmartScreen's *"More info → Run anyway"* prompt:
```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 dist\HVGuard.exe
```
Without a cert, SmartScreen will show a warning the first time (normal for inner-circle tools).
**Never** package the crack's binaries or links.
