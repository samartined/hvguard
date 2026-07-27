#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase A of the runbook (doc 03) - Inventory and chain of custody of the sample.

STATIC, READ-ONLY analysis. This script NEVER executes, loads, or modifies the sample:
it only opens it in binary read mode ('rb') to hash, classify, and measure entropy.

Purpose (doc 03, Phase A):
  1. List the sample recursively; record size and SHA-256 of each file -> hashes.csv
  2. Classify by type (PE executable, .sys driver, DLL, script, doc, archive, ...)
  3. Entropy per file (packing/encryption detection)
Also: flags files that match the bypass IOCs (doc 02 section 1) for later triage.

Design (quality criteria, doc 04):
  - Deterministic and auditable: sorted traversal, each row traced to its path/offset/magic.
  - No third-party dependencies (stdlib only): PE classification is done by parsing the header
    by hand; 'pefile'/'capstone' are reserved for Phase B.
  - Writes ONLY to the output directory (findings/), never inside the sample.
  - No silent skips: files whose hash is skipped due to size are counted and listed explicitly.

PE classification (without pefile):
  MZ -> the PE header is located (e_lfanew @0x3C), Machine, Characteristics and Subsystem are read.
  Driver  = .sys extension  or  Subsystem == 1 (NATIVE).
  DLL     = IMAGE_FILE_DLL flag (0x2000) in Characteristics.
  EXE     = the rest of PE.

Typical usage:
  python3 phase-a-inventory.py --sample-root /mnt/sample-iso \
      --out-dir ./findings
  # Optional: master hash of the ISO artifact (slow, ~tens of min over vboxsf):
  #   --iso-file "<sample-root>/<image>.iso"
"""

import argparse
import csv
import math
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

TOOL_NAME = "phase-a-inventory"
TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------------------------------
# Bypass IOCs (doc 02 section 1) + family patterns. Compared against the lowercase base name.
# ---------------------------------------------------------------------------------------------------
IOC_EXACT = {
    "hypervisor-launcher.exe": "user-mode loader for the bypass",
    "simplesvm.sys":           "AMD SVM hypervisor driver (Ring -1)",
    "hyperkd.sys":             "supporting kernel driver",
    "hyperhv.dll":             "VMM core (contains the documented Ring -1 vulnerabilities)",
    "hyperevade.dll":          "VM evasion / anti-detection layer",
    "vbs.cmd":                 "security toggle script (option 1 turns VBS off / option 3 reverts)",
    "denuvowo.nfo":            "bypass documentation",
    "denuoowo_src.7z":         "bypass source code (for reading/diffing, NOT building)",
    "_info.txt":               "instructions from the official info sheet",
}

def ioc_reason(basename: str, ext: str) -> str:
    """Returns the reason if the file is relevant to the bypass, or '' if it is not."""
    b = basename.lower()
    if b in IOC_EXACT:
        return "EXACT IOC: " + IOC_EXACT[b]
    reasons = []
    if ext == ".sys":
        reasons.append("kernel driver (.sys): candidate for an unsigned Ring -1/support driver")
    if b.startswith("hyper") and ext in (".dll", ".sys", ".exe"):
        reasons.append("'hyper' prefix + binary: VMM/hypervisor component")
    if "svm" in b or "vmx" in b:
        reasons.append("svm/vmx token: related to AMD/Intel virtualization")
    if "efiguard" in b:
        reasons.append("EfiGuard: UEFI bootkit that disables PatchGuard/DSE (boot variant)")
    if any(t in b for t in ("denuvo", "denuo", "owo")):
        reasons.append("denuvo/denuo/owo token: DenuvOwO attribution")
    if any(t in b for t in ("goldberg", "coldclient", "steamemu", "steam_api", "steamclient")):
        reasons.append("Steam emulation (sibling crack family)")
    if ext == ".nfo":
        reasons.append(".nfo file: typical release documentation")
    return "; ".join(reasons)

# ---------------------------------------------------------------------------------------------------
# File signatures by header bytes.
# ---------------------------------------------------------------------------------------------------
MAGICS = [
    (b"MZ",                      "pe"),          # Windows executable (PE/DOS) - refined further below
    (b"ArC\x01",                 "archive-freearc"),   # FreeArc (.arc) - container typical of ElAmigos
    (b"Inno Setup",              "installer-inno-data"),# Inno Setup: data file (setup-0.bin)
    (b"idska32\x1a",             "installer-inno-slice"),# Inno Setup: disk slice (setup-N.bin)
    (b"zlb\x1a",                 "installer-inno-zlb"), # Inno Setup: compressed zlb block
    (b"\x37\x7A\xBC\xAF\x27\x1C","archive-7z"),
    (b"PK\x03\x04",              "archive-zip"),
    (b"PK\x05\x06",              "archive-zip"),  # empty zip
    (b"PK\x07\x08",              "archive-zip"),  # zip spanned
    (b"Rar!\x1A\x07",           "archive-rar"),
    (b"MSCF",                    "archive-cab"),
    (b"\x1F\x8B",                "archive-gzip"),
    (b"ustar",                   "archive-tar"),  # (offset 257 normally; weak heuristic)
    (b"%PDF",                    "document-pdf"),
    (b"\x7FELF",                 "elf"),          # should not appear (Linux binary)
    (b"\x89PNG",                 "image-png"),
    (b"\xFF\xD8\xFF",            "image-jpeg"),
    (b"GIF8",                    "image-gif"),
]

SCRIPT_EXT = {".cmd", ".bat", ".ps1", ".psm1", ".vbs", ".js", ".wsf", ".sh", ".py", ".pl"}
CONFIG_EXT = {".inf", ".ini", ".reg", ".xml", ".json", ".yaml", ".yml", ".cfg", ".conf", ".manifest"}
DOC_EXT    = {".txt", ".nfo", ".md", ".rtf", ".log", ".diz", ".readme", ".url"}
IMAGE_EXT  = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp"}

MACHINE = {
    0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x01C0: "arm",
    0x01C4: "armnt", 0x0200: "ia64", 0x0EBC: "efi-byte-code",
}
SUBSYSTEM = {
    0: "unknown", 1: "native", 2: "gui", 3: "console", 5: "os2", 7: "posix",
    9: "wince", 10: "efi-app", 11: "efi-boot-driver", 12: "efi-runtime-driver", 13: "efi-rom",
}
IMAGE_FILE_DLL = 0x2000


def classify_pe(header: bytes, ext: str):
    """Parses the PE header by hand. Returns (category, detail) or None if not a valid PE."""
    try:
        if len(header) < 0x40 or header[:2] != b"MZ":
            return None
        e_lfanew = int.from_bytes(header[0x3C:0x40], "little")
        if e_lfanew <= 0 or e_lfanew + 24 > len(header):
            return ("pe-dos", "MZ without a PE header accessible in the read prefix")
        if header[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return ("pe-dos", "MZ (DOS) without PE signature")
        coff = e_lfanew + 4
        machine = int.from_bytes(header[coff:coff + 2], "little")
        characteristics = int.from_bytes(header[coff + 18:coff + 20], "little")
        opt = coff + 20
        subsystem = None
        # Subsystem is at offset 68 of the Optional Header (same in PE32 and PE32+).
        if opt + 70 <= len(header):
            magic = int.from_bytes(header[opt:opt + 2], "little")
            subsystem = int.from_bytes(header[opt + 68:opt + 70], "little")
        else:
            magic = None
        ts = int.from_bytes(header[coff + 4:coff + 8], "little")
        arch = MACHINE.get(machine, f"0x{machine:04X}")
        subs = SUBSYSTEM.get(subsystem, str(subsystem)) if subsystem is not None else "?"
        is_dll = bool(characteristics & IMAGE_FILE_DLL)
        # Compilation timestamp (informational; 0 or odd values are possible).
        ts_str = "0"
        if ts:
            try:
                ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OverflowError, OSError, ValueError):
                ts_str = f"raw:{ts}"
        detail = f"arch={arch};subsys={subs};dll={int(is_dll)};pe={'32+' if magic==0x20b else '32' if magic==0x10b else '?'};ts={ts_str}"
        if ext == ".sys" or subsystem == 1:
            return ("pe-driver", detail)
        if is_dll or ext == ".dll":
            return ("pe-dll", detail)
        return ("pe-exe", detail)
    except Exception as e:  # pragma: no cover - defensive
        return ("pe-error", f"parse-error:{e}")


def classify(header: bytes, basename: str, ext: str, size: int):
    """General classification by magic + extension. Returns (category, detail)."""
    if size == 0:
        return ("empty", "0 bytes")
    # 1) Magic bytes
    matched = None
    for sig, label in MAGICS:
        if header.startswith(sig):
            matched = label
            break
    if matched == "pe":
        pe = classify_pe(header, ext)
        if pe:
            return pe
        return ("pe-exe", "MZ")
    if matched:
        return (matched, f"magic={header[:8].hex()}")
    # 2) Extension
    if ext in SCRIPT_EXT:
        return ("script", f"ext={ext}")
    if ext in CONFIG_EXT:
        return ("config", f"ext={ext}")
    if ext in DOC_EXT:
        return ("document", f"ext={ext}")
    if ext in IMAGE_EXT:
        return ("image", f"ext={ext}")
    # 3) Text vs binary heuristic over the prefix
    sample = header[:512]
    if sample:
        nontext = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
        if nontext == 0:
            return ("text", "printable ASCII/UTF-8 prefix")
    return ("data", f"binary without a recognized signature; magic={header[:8].hex()}")


def entropy_from_bytes(data):
    """
    Shannon entropy (bits/byte, 0..8) over a SAMPLE of bytes.
    Uses collections.Counter (C-level histogram) -> avoids the per-byte loop in Python,
    which is prohibitive over multi-GB files (~12 MB/s). Entropy is always computed
    over a bounded sample; SHA-256, by contrast, is computed over the whole file (hashlib, C).
    """
    n = len(data)
    if n == 0:
        return 0.0
    from collections import Counter
    ent = 0.0
    for cnt in Counter(data).values():
        p = cnt / n
        ent -= p * math.log2(p)
    return ent


def process_file(abspath, relpath, size, args, relevant):
    """
    Returns a row dict. A single read pass computes SHA-256 and entropy when the full file is
    hashed; if skipped due to size, only a prefix is read for entropy+magic.
    """
    import hashlib
    ext = os.path.splitext(relpath)[1].lower()
    basename = os.path.basename(relpath)
    row = {
        "relative_path": relpath,
        "size_bytes": size,
        "category": "",
        "detail": "",
        "sha256": "",
        "hash_status": "",
        "entropy_bits_per_byte": "",
        "entropy_scope": "",
        "magic_hex": "",
        "is_relevant": "1" if relevant else "0",
        "ioc_reason": "",
        "file_desc": "",
        "mtime_utc": "",
    }
    try:
        st = os.stat(abspath)
        row["mtime_utc"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        pass

    # The file is fully hashed if: it fits under the cap, or --hash-all, or it is relevant (IOC)
    # regardless of size.
    do_full_hash = args.hash_all or relevant or (size <= args.max_hash_bytes)

    ent_cap = max(0, args.entropy_sample_bytes)
    sample = bytearray()   # bounded sample for entropy (does not grow beyond ent_cap)
    header = b""
    CHUNK = 1024 * 1024

    try:
        with open(abspath, "rb", buffering=0) as f:
            if do_full_hash:
                h = hashlib.sha256()
                first = True
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    if first:
                        header = chunk[:4096]   # enough to locate the PE Optional Header
                        first = False
                    h.update(chunk)                     # full SHA-256 at C level (fast)
                    if len(sample) < ent_cap:           # entropy: only until the sample is filled
                        sample += chunk[:ent_cap - len(sample)]
                row["sha256"] = h.hexdigest()
                row["hash_status"] = "OK"
            else:
                # No full hash (counted as skipped); only a prefix for entropy + magic.
                prefix = f.read(ent_cap)
                header = prefix[:4096]
                sample = bytearray(prefix)
                row["sha256"] = ""
                row["hash_status"] = f"SKIPPED_SIZE(>{args.max_hash_bytes})"
    except (OSError, PermissionError) as e:
        row["hash_status"] = f"ERROR:{e.__class__.__name__}"
        row["category"] = "unreadable"
        row["detail"] = str(e)
        return row

    row["magic_hex"] = header[:8].hex()
    cat, detail = classify(header, basename, ext, size)
    row["category"] = cat
    row["detail"] = detail
    row["entropy_bits_per_byte"] = f"{entropy_from_bytes(sample):.3f}" if sample else ""
    # Entropy scope: FULL if the file fits in the sample and was hashed whole; otherwise sampled.
    row["entropy_scope"] = "FULL" if (do_full_hash and size <= ent_cap) else f"SAMPLED:{len(sample)}B"

    if relevant:
        row["ioc_reason"] = ioc_reason(basename, ext)
        # Enrich the relevant files (small set) with `file -b` if available.
        if args.use_file_cmd:
            try:
                out = subprocess.run(["file", "-b", abspath], capture_output=True, text=True, timeout=30)
                row["file_desc"] = out.stdout.strip()[:300]
            except (OSError, subprocess.SubprocessError):
                row["file_desc"] = ""
    return row


def hash_iso_master(iso_path):
    """SHA-256 of the external ISO artifact (master chain-of-custody evidence). Slow."""
    import hashlib
    h = hashlib.sha256()
    size = os.path.getsize(iso_path)
    done = 0
    t0 = time.time()
    CHUNK = 8 * 1024 * 1024
    with open(iso_path, "rb", buffering=0) as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if done % (1024 * 1024 * 1024) < CHUNK:  # every ~1 GiB
                pct = 100.0 * done / size if size else 0
                sys.stderr.write(f"  [iso-hash] {done/1e9:.1f}/{size/1e9:.1f} GB ({pct:.1f}%) {time.time()-t0:.0f}s\n")
                sys.stderr.flush()
    return h.hexdigest(), size


def main():
    ap = argparse.ArgumentParser(description="Phase A - inventory, SHA-256, and classification of the sample (read-only).")
    ap.add_argument("--sample-root", required=True, help="Root of the mounted sample (e.g. /mnt/sample-iso).")
    ap.add_argument("--out-dir", default="./findings", help="Output directory (findings/).")
    ap.add_argument("--max-hash-bytes", type=int, default=2 * 1024 * 1024 * 1024,
                    help="Files bigger than this are inventoried but NOT fully hashed (unless IOC or --hash-all). Default: 2 GiB.")
    ap.add_argument("--hash-all", action="store_true", help="Hash ALL files regardless of size (slow).")
    ap.add_argument("--entropy-sample-bytes", type=int, default=8 * 1024 * 1024,
                    help="Prefix read for entropy on files that were not hashed. Default: 8 MiB.")
    ap.add_argument("--iso-file", default=None, help="Optional: path to the external ISO for a master hash (slow).")
    ap.add_argument("--no-file-cmd", dest="use_file_cmd", action="store_false",
                    help="Do not invoke `file` to enrich relevant files.")
    ap.add_argument("--progress-every", type=int, default=200, help="Report progress every this many files.")
    ap.set_defaults(use_file_cmd=True)
    args = ap.parse_args()

    sample_root = os.path.abspath(args.sample_root)
    out_dir = os.path.abspath(args.out_dir)

    # --- Safety guards ---
    if not os.path.isdir(sample_root):
        sys.exit(f"ERROR: sample-root is not a directory: {sample_root}")
    # Never write inside the sample.
    if out_dir == sample_root or out_dir.startswith(sample_root + os.sep):
        sys.exit(f"ERROR: out-dir is inside sample-root. The sample is READ-ONLY. Choose another output.")
    os.makedirs(out_dir, exist_ok=True)

    started = datetime.now(timezone.utc)
    sys.stderr.write(f"[{TOOL_NAME}] scanning {sample_root} ...\n")

    # --- Deterministic traversal ---
    files = []
    for dirpath, dirnames, filenames in os.walk(sample_root):
        dirnames.sort()
        for name in sorted(filenames):
            ap_ = os.path.join(dirpath, name)
            if not os.path.isfile(ap_) or os.path.islink(ap_):
                continue
            try:
                size = os.path.getsize(ap_)
            except OSError:
                size = -1
            rel = os.path.relpath(ap_, sample_root)
            files.append((ap_, rel, size))
    files.sort(key=lambda t: t[1].lower())

    total_files = len(files)
    sys.stderr.write(f"[{TOOL_NAME}] {total_files} files. Processing...\n")

    rows = []
    t0 = time.time()
    bytes_seen = 0
    for i, (abspath, rel, size) in enumerate(files, 1):
        basename = os.path.basename(rel)
        ext = os.path.splitext(rel)[1].lower()
        relevant = bool(ioc_reason(basename, ext))
        row = process_file(abspath, rel, size, args, relevant)
        rows.append(row)
        bytes_seen += max(size, 0)
        if i % args.progress_every == 0 or i == total_files:
            el = time.time() - t0
            sys.stderr.write(f"  {i}/{total_files} files, {bytes_seen/1e9:.2f} GB seen, {el:.0f}s\n")
            sys.stderr.flush()

    # --- Master ISO hash (optional) ---
    iso_hash = None
    iso_size = None
    if args.iso_file:
        if os.path.isfile(args.iso_file):
            sys.stderr.write(f"[{TOOL_NAME}] master ISO hash (slow): {args.iso_file}\n")
            iso_hash, iso_size = hash_iso_master(args.iso_file)
        else:
            sys.stderr.write(f"[{TOOL_NAME}] WARNING: --iso-file does not exist: {args.iso_file}\n")

    finished = datetime.now(timezone.utc)

    # --- CSV output ---
    csv_path = os.path.join(out_dir, "hashes.csv")
    fields = ["relative_path", "size_bytes", "category", "detail", "sha256", "hash_status",
              "entropy_bits_per_byte", "entropy_scope", "magic_hex", "is_relevant", "ioc_reason",
              "file_desc", "mtime_utc"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # --- Aggregates for the report ---
    from collections import defaultdict
    cat_count = defaultdict(int)
    cat_size = defaultdict(int)
    for r in rows:
        cat_count[r["category"]] += 1
        cat_size[r["category"]] += max(r["size_bytes"], 0)
    skipped = [r for r in rows if r["hash_status"].startswith("SKIPPED_SIZE")]
    errors = [r for r in rows if r["hash_status"].startswith("ERROR")]
    relevant_rows = [r for r in rows if r["is_relevant"] == "1"]
    high_entropy = sorted(
        [r for r in rows if r["entropy_bits_per_byte"] and float(r["entropy_bits_per_byte"]) >= 7.2],
        key=lambda r: float(r["entropy_bits_per_byte"]), reverse=True)
    total_size = sum(max(r["size_bytes"], 0) for r in rows)
    hashed_ok = [r for r in rows if r["hash_status"] == "OK"]

    # --- Markdown report writing ---
    md_path = os.path.join(out_dir, "inventory-report.md")
    def h(n): return f"{n/1e9:.2f} GB" if n >= 1e9 else (f"{n/1e6:.2f} MB" if n >= 1e6 else f"{n} B")
    with open(md_path, "w", encoding="utf-8") as md:
        md.write("# Phase A - Inventory and chain of custody of the sample\n\n")
        md.write(f"- **Tool:** `{TOOL_NAME}` v{TOOL_VERSION}\n")
        md.write(f"- **Start (UTC):** {started.strftime('%Y-%m-%dT%H:%M:%SZ')}  ")
        md.write(f"**End (UTC):** {finished.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        md.write(f"- **Sample root:** `{sample_root}`  *(mounted READ-ONLY)*\n")
        md.write(f"- **Output:** `{csv_path}`, `{md_path}`\n")
        md.write(f"- **Hash mode:** {'ALL (--hash-all)' if args.hash_all else f'cap {h(args.max_hash_bytes)} (IOCs always full)'}\n\n")
        md.write("> **Static, read-only** analysis. No sample binary is executed or loaded. "
                 "Windows PEs cannot run on this Linux VM (zero execution risk).\n\n")

        if iso_hash:
            md.write("## Master evidence (ISO artifact)\n\n")
            md.write(f"- **File:** `{args.iso_file}`\n- **Size:** {iso_size} B ({h(iso_size)})\n")
            md.write(f"- **SHA-256:** `{iso_hash}`\n\n")
        elif args.iso_file:
            md.write("## Master evidence (ISO artifact)\n\n- (not computed)\n\n")

        md.write("## Totals\n\n")
        md.write(f"- Files: **{total_files}**  |  Total size: **{h(total_size)}** ({total_size} B)\n")
        md.write(f"- Fully hashed (SHA-256 OK): **{len(hashed_ok)}**\n")
        md.write(f"- Hash skipped due to size: **{len(skipped)}**  |  Read errors: **{len(errors)}**\n")
        md.write(f"- Files flagged as **relevant to the bypass (IOC)**: **{len(relevant_rows)}**\n\n")

        md.write("## Breakdown by category\n\n| Category | Count | Size |\n|---|---:|---:|\n")
        for cat in sorted(cat_count, key=lambda c: cat_size[c], reverse=True):
            md.write(f"| {cat} | {cat_count[cat]} | {h(cat_size[cat])} |\n")
        md.write("\n")

        md.write("## Artifacts relevant to the bypass (triage focus)\n\n")
        if relevant_rows:
            md.write("| Path | Category | Size | Entropy | SHA-256 | IOC reason | `file` |\n")
            md.write("|---|---|---:|---:|---|---|---|\n")
            for r in sorted(relevant_rows, key=lambda r: r["relative_path"].lower()):
                sha = r["sha256"][:16] + "..." if r["sha256"] else "(no hash)"
                md.write(f"| `{r['relative_path']}` | {r['category']} | {h(r['size_bytes'])} | "
                         f"{r['entropy_bits_per_byte']} | `{sha}` | {r['ioc_reason']} | {r['file_desc']} |\n")
            md.write("\n> Full SHA-256 values are in `hashes.csv`.\n\n")
        else:
            md.write("_No file matched the bypass IOC patterns under this root._ "
                     "Check whether the sample is inside a sub-container (installer, nested 7z) not yet extracted.\n\n")

        md.write("## High-entropy files (possible packing/encryption, entropy >= 7.2)\n\n")
        if high_entropy:
            md.write("| Path | Category | Size | Entropy | Scope |\n|---|---|---:|---:|---|\n")
            for r in high_entropy[:40]:
                md.write(f"| `{r['relative_path']}` | {r['category']} | {h(r['size_bytes'])} | "
                         f"{r['entropy_bits_per_byte']} | {r['entropy_scope']} |\n")
            if len(high_entropy) > 40:
                md.write(f"\n_({len(high_entropy)-40} more rows in `hashes.csv`)._\n")
            md.write("\n")
        else:
            md.write("_None above the threshold._\n\n")

        if skipped:
            md.write("## Hash skipped due to size (counted, NOT silent)\n\n")
            md.write(f"{len(skipped)} files exceed the cap of {h(args.max_hash_bytes)}. "
                     "They are inventoried (size, category, prefix entropy) but without a full SHA-256. "
                     "Re-run with `--hash-all` to hash them.\n\n")
            md.write("| Path | Category | Size |\n|---|---|---:|\n")
            for r in sorted(skipped, key=lambda r: r["size_bytes"], reverse=True)[:25]:
                md.write(f"| `{r['relative_path']}` | {r['category']} | {h(r['size_bytes'])} |\n")
            if len(skipped) > 25:
                md.write(f"\n_({len(skipped)-25} more in `hashes.csv`)._\n")
            md.write("\n")

        if errors:
            md.write("## Read errors\n\n| Path | Status |\n|---|---|\n")
            for r in errors[:50]:
                md.write(f"| `{r['relative_path']}` | {r['hash_status']} |\n")
            md.write("\n")

        md.write("## Next step\n\n")
        md.write("- **Phase B (PE triage)** on the relevant artifacts: headers, Authenticode signature, "
                 "imports (ZwLoadDriver, RegSetValueEx, VMX/SVM intrinsics, network/injection) and exports "
                 "(`hyperhv.dll`/`hyperevade.dll`). Requires installing `pefile` (and `capstone` for Phase C).\n")
        md.write("- If the bypass components do not appear here, they are inside an installer or a nested "
                 "`.7z`/`.zip`: locate it by name and extract it to a working directory "
                 "(`/tmp` or `~/work`, **never** over the sample) to inventory it separately.\n")

    # --- Summary to stdout ---
    print(f"[{TOOL_NAME}] Done.")
    print(f"  Files:               {total_files}  ({h(total_size)})")
    print(f"  Hashed OK:           {len(hashed_ok)}")
    print(f"  Hash skipped:        {len(skipped)}   Errors: {len(errors)}")
    print(f"  Relevant (IOC):      {len(relevant_rows)}")
    print(f"  High entropy >=7.2:  {len(high_entropy)}")
    if iso_hash:
        print(f"  ISO SHA-256:         {iso_hash}")
    print(f"  CSV:    {csv_path}")
    print(f"  Report: {md_path}")


if __name__ == "__main__":
    main()
