# PE triage (Phase B) - installer toolchain, extracted to a scratch directory
Generated: 2026-07-13T09:21:43Z  ·  READ-ONLY

## CLS-MSC.dll  (x86, DLL, gui)
- SHA-256: `6d3d6b0ff25fd2ac2c8d478b068af55cb053d9b2c08c53964d6559c7c8b8047d`
- Size: 342016 B  ·  Compiled: 1992-06-19  ·  Signature: ABSENT (unsigned)
- Imports: 39  ·  Max section entropy: 7.12
  - no network/injection/persistence APIs
  - exports: ClsMain
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## CLS-srep.dll  (x86, DLL, gui)
- SHA-256: `af4379f3d8e12938a2f4e6d8f7d8f135181c415fa6c443b27eb44c3be173b2ef`
- Size: 87552 B  ·  Compiled: 2013-08-10  ·  Signature: ABSENT (unsigned)
- Imports: 81  ·  Max section entropy: 6.6
  - ⚠ crypto/anti: IsDebuggerPresent
  - exports: ClsMain
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## ISDone.dll  (x86, DLL, gui)
- SHA-256: `bb8a0245dcc5c10a1c7181bad509b65959855009a8105863ef14f2bb5b38ac71`
- Size: 463360 B  ·  Compiled: 1992-06-19  ·  Signature: ABSENT (unsigned)
- Imports: 194  ·  Max section entropy: 6.65
  - ⚠ network: SendMessageA
  - ⚠ process: CreateProcessA
  - exports: ChangeLanguage, Exec2, FileSearchInit, IS7zipExtract, ISArcExtract, ISDoneInit, ISDoneStop, ISExec, ISFindFiles, ISFindFree, ISGetName, ISPackZIP
- **Verdict:** REVIEW -> NETWORK

## callbackctrl.dll  (x86, DLL, gui)
- SHA-256: `68f42a7823ed7ee88a5c59020ac52d4bbcadf1036611e96e470d986c8faa172d`
- Size: 4096 B  ·  Compiled: 2010-02-26  ·  Signature: ABSENT (unsigned)
- Imports: 4  ·  Max section entropy: 3.85
  - no network/injection/persistence APIs
  - exports: wrapcallbackaddr
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## cls-bpk.dll  (x86, DLL, console)
- SHA-256: `20c1c8f1a70470e18c898d35136fcade1fa1cabdd069c564415debfd1a26c403`
- Size: 232960 B  ·  Compiled: 2017-12-29  ·  Signature: ABSENT (unsigned)
- Imports: 73  ·  Max section entropy: 6.46
  - ⚠ crypto/anti: IsDebuggerPresent
  - exports: ClsMain
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## cls-lolz.dll  (x86, DLL, gui)
- SHA-256: `87df573ac240e09ea4941e169fb2d15d5316a1b0e053446b8144e04b1154f061`
- Size: 16384 B  ·  Compiled: 2017-12-29  ·  Signature: ABSENT (unsigned)
- Imports: 21  ·  Max section entropy: 6.26
  - ⚠ process: CreateProcessA
  - exports: ClsMain
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## cls-lolz_x64.exe  (x64, EXE, console)
- SHA-256: `d92f7c60256509f74e36d9b5aab041fe44999b1a3910d70aa83c9d01f062ea29`
- Size: 343040 B  ·  Compiled: 2018-12-30  ·  Signature: ABSENT (unsigned)
- Imports: 98  ·  Max section entropy: 6.6
  - ⚠ crypto/anti: IsDebuggerPresent
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## cls-lolz_x86.exe  (x86, EXE, console)
- SHA-256: `6ea07aa4f5565ac289402ade3b2e52bf8089ad6185e0ecf0e1f36cea39c091a9`
- Size: 312320 B  ·  Compiled: 2018-12-30  ·  Signature: ABSENT (unsigned)
- Imports: 96  ·  Max section entropy: 6.64
  - ⚠ crypto/anti: IsDebuggerPresent
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## facompress.dll  (x86, DLL, gui)
- SHA-256: `17a9ffdf381f7a9f6cdfc85b157fc6cf80cd4b45ed8ad43edac73008923501a0`
- Size: 364032 B  ·  Compiled: 2014-03-15  ·  Signature: ABSENT (unsigned)
- Imports: 89  ·  Max section entropy: 6.59
  - ⚠ crypto/anti: IsDebuggerPresent
  - exports: CrcUpdate, Fast_AesCtr_Code, GRZip_CompressBlock, GRZip_DecompressBlock, GRZip_GetAdaptiveBlockSize, SetCompressionThreads, Set_compress_all_at_once, dict_compress, dict_decompress, lzma_compress2, lzma_decompress2, lzp_compress
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## facompress_mt.dll  (x86, DLL, gui)
- SHA-256: `7eeb2c50920e30544e2f180b0c39488501372a8f8bd8393bcb095353e9114cde`
- Size: 209408 B  ·  Compiled: 2014-03-15  ·  Signature: ABSENT (unsigned)
- Imports: 79  ·  Max section entropy: 6.62
  - ⚠ crypto/anti: IsDebuggerPresent
  - exports: SetCompressionThreads, Set_compress_all_at_once, ppmd_de_compress
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## srep64.exe  (x64, EXE, console)
- SHA-256: `0a5c85eb11dc7130c4191b9899a4f06889861f80bfb104fe167d01a52d04c755`
- Size: 509440 B  ·  Compiled: 1970-01-01  ·  Signature: ABSENT (unsigned)
- Imports: 177  ·  Max section entropy: 6.38
  - ⚠ process: CreateProcessW, ShellExecuteExW
  - URLs: http://freearc.org/research/SREP39.aspx
- **Verdict:** REVIEW -> URLs

## unarc.dll  (x86, DLL, console)
- SHA-256: `89952411324163a635942db33dd0087508e20d112e1e75403dc1d5e852927dd7`
- Size: 328192 B  ·  Compiled: 2012-12-12  ·  Signature: ABSENT (unsigned)
- Imports: 154  ·  Max section entropy: 6.69
  - ⚠ process: CreateProcessW, ShellExecuteExW
  - exports: FreeArcExtract, UnloadDLL
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)

## wintb.dll  (x86, DLL, console)
- SHA-256: `1910537aa95684142250ca0c7426a0b5f082e39f6fbdbdba649aecb179541435`
- Size: 16384 B  ·  Compiled: 2012-10-28  ·  Signature: ABSENT (unsigned)
- Imports: 55  ·  Max section entropy: 5.8
  - no network/injection/persistence APIs
  - exports: SetTaskBarOverlayIcon, SetTaskBarProgressState, SetTaskBarProgressValue, SetTaskBarThumbnailTooltip, SetTaskBarTitle, TaskBarAddButton, TaskBarButtonEnabled, TaskBarButtonImage, TaskBarButtonToolTip, TaskBarCreateButtons, Win6TaskBarV1_0A, Win6TaskBarV1_0B
- **Verdict:** OK (no payload indicators; consistent with a codec/utility)
