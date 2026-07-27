# Contributing

HVGuard is a defensive project studying and mitigating a hypervisor-based DRM bypass. The content
rules below exist to keep it that way; they are not style preferences. The full operating rules for
anyone (human or agent) working in this repo are in [`CLAUDE.md`](CLAUDE.md) — read that first. This
file does not repeat it, only points at the parts most relevant to a pull request.

## Content rules

- No bypass, crack, or DRM-circumvention code, in source or binary form — not even a "minimal repro."
- No samples. Do not attach crack binaries, ISOs, installers, or any part of a pirated release to an
  issue or PR. See `SECURITY.md` for the same rule on vulnerability reports.
- No links to releases, mirrors, or magnet links for the bypass, anywhere in the repo.
- Detection content (`defense/telemetry/sigma/`, `defense/telemetry/yara/`) must cite public sources
  (RE write-ups, upstream project source) for anything it matches on — never content derived from
  the bypass binary itself.

## User-facing strings

HVGuard's audience includes non-technical users in a harm-reduction context, so its copy is held to
a measurable bar, not a matter of taste:

- Any new or changed string in `launcher/lib/Modules/M*.ps1` or `launcher/lib/i18n/*.psd1` must pass
  `tools/check-plain-language.ps1` (zero jargon/acronyms in Layer 1 labels, glossed acronyms and a
  jargon budget in Layer 2 explanations — see the script's header for the exact rules).
- Every user-facing string must be added to **both** `launcher/lib/i18n/en.psd1` and `es.psd1` — and,
  for module-level strings, to both the `$en`/`$map_en` and `$es`/`$map_es` tables in the same file.
  A PR that adds a string in only one language will not pass review.
- If you introduce a new acronym, add it to `GLOSSARY.md` too.

## PowerShell files

`.ps1`/`.psd1`/`.psm1`/`.cmd` files are ASCII-only and CRLF line endings, to stay compatible with
Windows PowerShell 5.1, which this project deliberately still supports (`.gitattributes` enforces the
line endings; ASCII is a convention, not a linted rule, so check by eye). Accented characters belong
in the `.psd1` "chrome" strings only, which are loaded via explicit UTF-8 — not in a module's own
`$es`/`$en` string tables.

## Before opening a PR

Run the self-test: `HVGuard.ps1 -SelfTest` (or `dist\HVGuard.exe -SelfTest -SelfTestMs 1500` against
a packaged build) to confirm the GUI still renders and every module still initializes. If you touched
any user-facing string, also run `tools/check-plain-language.ps1` for both languages. If you touched
a `defense/T*.ps1` script, validate it on a disposable Windows VM with a snapshot per
`defense/TEST-RUNBOOK.md` — never against a real machine, and never by running the bypass to produce
the "before" state.
