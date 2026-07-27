#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Static PE triage (Phase B) - READ-ONLY, does not execute anything.
For each PE: SHA-256, architecture, Authenticode signature (presence), imports flagged as
PAYLOAD INDICATORS (network/injection/persistence/process) versus normal APIs, exports,
entropy per section, and notable strings (URLs/IPs). Emits a verdict per file.

Usage: python3 pe-triage.py <dir_or_file> [--out <report.md>]
"""
import argparse, hashlib, math, os, re, sys, datetime

try:
    import pefile
except Exception as e:
    sys.exit(f"pefile not available: {e}")

# --- Suspicious APIs (payload indicators, not just a plain codec) ---
SUSPECT = {
    "red": ["InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen",
            "WinHttpConnect", "send", "recv", "connect", "WSAStartup", "socket", "gethostbyname",
            "InternetReadFile", "URLDownloadToCacheFile"],
    "inyeccion": ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "NtMapViewOfSection",
                  "QueueUserApc", "SetWindowsHookEx", "NtUnmapViewOfSection", "RtlCreateUserThread",
                  "NtWriteVirtualMemory"],
    "proceso": ["CreateProcess", "ShellExecute", "WinExec", "NtCreateUserProcess"],
    "persistencia": ["RegSetValueEx", "RegCreateKeyEx", "CreateServiceA", "CreateServiceW",
                     "OpenSCManager", "schtasks"],
    "cripto/anti": ["CryptEncrypt", "CryptDecrypt", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess"],
    "driver": ["ZwLoadDriver", "NtLoadDriver", "ZwSetSystemInformation"],
}
URL_RE = re.compile(rb"https?://[A-Za-z0-9./_%:\-?=&#]{4,120}")
IP_RE  = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

def notable_strings(path, limit=12):
    data = open(path, "rb").read()
    urls = sorted(set(m.group().decode("latin1") for m in URL_RE.finditer(data)))
    ips  = sorted(set(m.group().decode("latin1") for m in IP_RE.finditer(data)))
    # discard trivial version-like IPs such as 0.0.0.0 / 127.x to reduce noise
    ips = [i for i in ips if not (i.startswith("0.") or i.startswith("127.") or i == "255.255.255.255")]
    return urls[:limit], ips[:limit]

MACHINE = {0x14c: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1c0: "arm"}
SUBSYS = {1: "native", 2: "gui", 3: "console"}

def analyze(path):
    r = {"file": os.path.basename(path), "size": os.path.getsize(path), "sha256": sha256(path)}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except Exception as e:
        r["type"] = "NO-PE"; r["detail"] = str(e); return r
    r["type"] = "PE"
    r["arch"] = MACHINE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    r["dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    r["subsystem"] = SUBSYS.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    try:
        r["timestamp"] = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, datetime.timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        r["timestamp"] = str(pe.FILE_HEADER.TimeDateStamp)
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    r["authenticode"] = "present" if sec.Size > 0 else "ABSENT (unsigned)"
    # imports
    imps = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for mod in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in mod.imports:
                if imp.name:
                    imps.append(imp.name.decode("latin1", "ignore"))
    r["import_count"] = len(imps)
    hits = {}
    for cat, apis in SUSPECT.items():
        found = sorted(set(i for i in imps for a in apis if a.lower() in i.lower()))
        if found:
            hits[cat] = found
    r["suspect"] = hits
    # exports
    exps = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if s.name:
                exps.append(s.name.decode("latin1", "ignore"))
    r["exports"] = exps[:20]
    # entropy
    ent = [(s.Name.rstrip(b"\x00").decode("latin1", "ignore"), round(s.get_entropy(), 2)) for s in pe.sections]
    r["sections"] = ent
    r["max_entropy"] = max((e for _, e in ent), default=0)
    r["urls"], r["ips"] = notable_strings(path)
    pe.close()
    return r

def verdict(r):
    if r.get("type") != "PE":
        return "n/a"
    flags = []
    if r["suspect"].get("red"): flags.append("NETWORK")
    if r["suspect"].get("inyeccion"): flags.append("INJECTION")
    if r["suspect"].get("persistencia"): flags.append("PERSISTENCE")
    if r["suspect"].get("driver"): flags.append("DRIVER")
    if r["urls"]: flags.append("URLs")
    if not flags:
        return "OK (no payload indicators; consistent with a codec/utility)"
    return "REVIEW -> " + ", ".join(flags)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    files = []
    if os.path.isdir(args.target):
        for n in sorted(os.listdir(args.target)):
            p = os.path.join(args.target, n)
            if os.path.isfile(p):
                files.append(p)
    else:
        files = [args.target]
    rows = [analyze(p) for p in files]
    out = []
    out.append(f"# PE triage (Phase B) - {args.target}")
    out.append(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  |  READ-ONLY\n")
    for r in rows:
        if r.get("type") == "NO-PE":
            continue
        out.append(f"## {r['file']}  ({r['arch']}, {'DLL' if r['dll'] else 'EXE'}, {r['subsystem']})")
        out.append(f"- SHA-256: `{r['sha256']}`")
        out.append(f"- Size: {r['size']} B  |  Compiled: {r['timestamp']}  |  Signature: {r['authenticode']}")
        out.append(f"- Imports: {r['import_count']}  |  Max section entropy: {r['max_entropy']}")
        if r["suspect"]:
            for cat, apis in r["suspect"].items():
                out.append(f"  - [!] {cat}: {', '.join(apis[:8])}")
        else:
            out.append("  - no network/injection/persistence APIs")
        if r["urls"]:
            out.append(f"  - URLs: {', '.join(r['urls'])}")
        if r["ips"]:
            out.append(f"  - IPs: {', '.join(r['ips'])}")
        if r["exports"]:
            out.append(f"  - exports: {', '.join(r['exports'][:12])}")
        out.append(f"- **Verdict:** {verdict(r)}\n")
    text = "\n".join(out)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
        print(f"\n[saved to {args.out}]")

if __name__ == "__main__":
    main()
