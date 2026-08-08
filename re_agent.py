#!/usr/bin/env python3
"""
re_agent.py — Exploit-First Binary Analysis Agent  (agent.md v1.3)

Usage:
  python3 re_agent.py <firmware_file> [options]

All parameters auto-detected from the binary.  Override flags are escape hatches
only when auto-detection fails.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Tuple

from models import Finding, TriageResult, SEVERITY_RANK, SEVERITY_ORDER
from toolkit.detector import detect_and_parse, BinaryInfo
from toolkit.mcu import resolve_mcu, resolve_mcu_or_default, MCUInfo
from toolkit.extractor import extract_all, fingerprint_rtos, parse_cortexm_vectors
from toolkit.tools import run_file, run_strings, run_binwalk, run_radare2, run_readelf

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║   re_agent — Exploit-First Binary Analysis Agent  v2.0      ║
║   AI Binary Toolkit  |  agent.md v2.0                       ║
╚══════════════════════════════════════════════════════════════╝"""

W = 74
_finding_counter = [0]


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list, cwd: str = None, input_data: bytes = None,
         timeout: int = 60, env: dict = None) -> Tuple[str, int]:
    try:
        r = subprocess.run(
            cmd, input=input_data, capture_output=True,
            timeout=timeout, cwd=cwd, env=env,
        )
        return (r.stdout + r.stderr).decode(errors="replace"), r.returncode
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]", -1
    except FileNotFoundError:
        return f"[tool not found: {cmd[0]}]", -1
    except Exception as exc:
        return f"[error: {exc}]", -1


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


_GHIDRA_FALLBACK_PATHS = [
    "/usr/share/ghidra",
    "/opt/ghidra",
    os.path.expanduser("~/ghidra"),
    os.path.expanduser("~/tools/ghidra"),
]

def _find_ghidra_home() -> str:
    """
    Return the Ghidra install directory.
    Checks GHIDRA_HOME env first, then common install locations.
    Returns empty string if not found.
    """
    env = os.environ.get("GHIDRA_HOME", "").strip()
    if env and os.path.isfile(os.path.join(env, "support", "analyzeHeadless")):
        return env
    for p in _GHIDRA_FALLBACK_PATHS:
        if os.path.isfile(os.path.join(p, "support", "analyzeHeadless")):
            return p
    return ""


def _next_id() -> str:
    _finding_counter[0] += 1
    return f"F-{_finding_counter[0]:03d}"


def _escalate(severity: str, steps: int = 1) -> str:
    idx = SEVERITY_RANK.get(severity, 2)
    return SEVERITY_ORDER[min(idx + steps, 4)]


def _bar(title: str) -> str:
    return f"\n┌─ {title} {'─' * max(0, W - len(title) - 3)}┐"


def _section(title: str, content: str) -> None:
    print(_bar(title))
    for line in content.strip().splitlines():
        print(f"│ {line}")
    print(f"└{'─' * W}┘")


def _status(tag: str, msg: str) -> None:
    symbols = {"*": "[*]", "+": "[+]", "!": "[!]", "~": "[~]", "-": "[-]"}
    print(f"{symbols.get(tag, tag)} {msg}")


def _write_temp(data: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return path


# ── STAGE 0 — Triage & Format Detection ───────────────────────────────────────

def stage0_triage(path: str, args) -> TriageResult:
    _section("STAGE 0", "Triage & Format Detection")
    info = detect_and_parse(path)

    # Detect arch from BinaryInfo
    arch = _resolve_arch(info, args)
    bits = _resolve_bits(info, args)
    endian = _resolve_endian(info, args)

    # MCU resolution
    controller_hint = args.controller or ""
    mcu = resolve_mcu(controller_hint) if controller_hint else _guess_mcu(info, arch, bits)
    mcu_desc = mcu.description if mcu else f"{arch} {bits}-bit (generic)"

    # OS type detection
    os_type = args.os_type or _detect_os_type(info, args)

    # Gap 5: xxd first-512-bytes — endianness hint + embedded magic markers
    _status("*", "xxd first-512-bytes scan...")
    xxd_out, _ = _run(["xxd", "-l", "512", path], timeout=10)
    if not xxd_out.startswith("["):
        # Look for magic markers that refine endianness / format hints
        if "ffd8ff" in xxd_out or "ffd9" in xxd_out:
            _status("+", "xxd: JPEG magic detected in first 512 bytes")
        if "504b03" in xxd_out:
            _status("+", "xxd: ZIP/APK magic detected")
        # Big-endian ARM hint: thumb BL instruction pattern
        if "f000" in xxd_out[:200] and args.endian not in ("le", "little"):
            pass  # refine if needed; endian already resolved above
    else:
        _status("~", "[TOOL_MISSING] xxd not found — skipping first-512 scan")

    _status("+", f"Format     : {info.format}")
    _status("+", f"Arch       : {arch} {bits}-bit  endian={endian}")
    _status("+", f"OS type    : {os_type}")
    _status("+", f"MCU        : {mcu_desc}")

    # Checksec for mitigation flags
    mitigations = _run_checksec(path, info)
    _status("+", f"NX={mitigations.get('nx')}  CANARY={mitigations.get('canary')}  "
                 f"PIE={mitigations.get('pie')}  RELRO={mitigations.get('relro')}")

    # RTOS fingerprint
    rtos_info = {}
    if os_type in ("RTOS", "Unknown"):
        rtos_info = fingerprint_rtos(info.raw_bytes)
        if rtos_info.get("detected"):
            _status("+", f"RTOS       : {rtos_info['detected']} "
                         f"({rtos_info.get('confidence', '?')})")
            if os_type == "Unknown":
                os_type = "RTOS"

    # Vector table for Cortex-M
    vector_table = {}
    if mcu and getattr(mcu, "thumb", False):
        vector_table = parse_cortexm_vectors(info.raw_bytes, mcu.flash_base)
        _status("+", f"Reset vec  : {vector_table.get('reset_handler', '?')}")

    # Filesystem extraction
    outdir = _extraction_dir(path)
    _status("*", "Running binwalk extraction...")
    extraction = extract_all(info.raw_bytes, outdir)
    has_fs = extraction.get("filesystems_found", 0) > 0
    extracted_path = ""
    if has_fs:
        # Find the first squashfs-root or similar directory
        extracted_path = _find_rootfs(outdir)
        _status("+", f"Filesystem : {extraction['filesystems_found']} found"
                     + (f" → {extracted_path}" if extracted_path else ""))
    else:
        _status("~", "No embedded filesystem extracted")

    load_addr = info.load_address or (mcu.flash_base if mcu else 0)
    entry_pt  = info.load_address or load_addr

    # A1: compute confidence from actual matched evidence, not hardcoded 0.8
    _linux_markers = [b"/lib/ld-linux", b"/lib/ld-musl", b"libc.so", b"libpthread"]
    if os_type == "Linux":
        matched = sum(1 for m in _linux_markers if m in info.raw_bytes)
        confidence = round(matched / len(_linux_markers), 2)
    elif rtos_info.get("confidence_score") is not None:
        confidence = rtos_info["confidence_score"]
    else:
        confidence = 0.5

    return TriageResult(
        format=info.format,
        arch=arch,
        bits=bits,
        endian=endian,
        os_type=os_type,
        mcu_match=mcu_desc,
        confidence=confidence,
        load_address=load_addr,
        entry_point=entry_pt,
        has_filesystem=has_fs,
        extracted_path=extracted_path,
        binary_info=info,
        mitigations=mitigations,
        rtos_info=rtos_info,
        vector_table=vector_table,
    )


def _resolve_arch(info: BinaryInfo, args) -> str:
    if args.arch:
        return args.arch
    arch_map = {
        "arm": "arm", "aarch64": "arm64", "x86": "x86", "x86_64": "x86_64",
        "mips": "mips", "riscv": "riscv", "xtensa": "xtensa", "avr": "avr",
    }
    if info.architecture:
        return arch_map.get(info.architecture, info.architecture)
    return "arm"


def _resolve_bits(info: BinaryInfo, args) -> str:
    if info.metadata.get("bits"):
        return str(info.metadata["bits"])
    if info.architecture in ("aarch64", "x86_64"):
        return "64"
    return "32"


def _resolve_endian(info: BinaryInfo, args) -> str:
    if args.endian:
        return args.endian
    if info.metadata.get("endian"):
        e = info.metadata["endian"]
        return "little" if "little" in e else "big"
    return "little"


def _guess_mcu(info: BinaryInfo, arch: str, bits: str):
    from toolkit.mcu import resolve_mcu_or_default
    return resolve_mcu_or_default("", "RTOS")


def _detect_os_type(info: BinaryInfo, args) -> str:
    data = info.raw_bytes
    if info.format == "elf":
        linux_markers = [b"/lib/ld-linux", b"/lib/ld-musl", b"libc.so", b"libpthread"]
        if any(m in data for m in linux_markers):
            return "Linux"
    # Only VxWorks gets a dedicated pipeline; all other RTOS markers route to Unknown
    vxworks_markers = [b"VxWorks", b"Wind River", b"vxworks", b"taskSpawn",
                       b"wdbTgtSvr", b"usrRoot", b"WIND version"]
    if any(m in data for m in vxworks_markers):
        return "RTOS"
    return "Unknown"


def os_confirmation_checkpoint(triage: TriageResult, args) -> str:
    """
    OS Confirmation Checkpoint — only user interaction in the entire pipeline.

    Prints detected OS + confidence + evidence.
    Returns the confirmed OS string: 'Linux' or 'VxWorks'.
    --non-interactive skips the prompt and accepts auto-detection.
    """
    detected_os  = triage.os_type
    rtos_info    = triage.rtos_info
    rtos_name    = rtos_info.get("detected", "")
    conf_score   = triage.confidence

    # Resolve specific name from RTOS detection
    if detected_os == "RTOS" and rtos_name == "VxWorks":
        specific_os = "VxWorks"
    elif detected_os == "RTOS":
        # Non-VxWorks RTOS detected — no dedicated pipeline, route to Linux
        specific_os = "Linux"
    else:
        specific_os = detected_os if detected_os in ("Linux",) else "Linux"

    print()
    print("┌─ OS CONFIRMATION CHECKPOINT " + "─" * 44 + "┐")
    print(f"│  Detected OS  : {detected_os}"
          + (f" ({rtos_name})" if rtos_name and rtos_name != detected_os else ""))
    print(f"│  Confidence   : {conf_score:.0%}")
    if rtos_info.get("candidates"):
        cands = ", ".join(
            f"{k}({len(v)})" for k, v in rtos_info["candidates"].items()
        )
        print(f"│  Candidates   : {cands}")
    print(f"│  Format       : {triage.format}  Arch: {triage.arch}  "
          f"Endian: {triage.endian}")
    print("│")
    print("│  Pipeline to run:")
    if specific_os == "VxWorks":
        print("│    → VxWorks RTOS Analysis Pipeline (Stages VX1–VX6)")
    else:
        print("│    → Linux Firmware Analysis Pipeline (Stages L1–L6)")
    print("└" + "─" * 73 + "┘")

    if getattr(args, "non_interactive", False):
        _status("+", f"--non-interactive: auto-confirming OS = {specific_os}")
        return specific_os

    # Interactive prompt — only Linux and VxWorks are supported pipelines
    choices = ["Linux", "VxWorks"]
    print()
    print(f"  Accept detected OS '{specific_os}'? "
          f"[Y/n or type override: {'/'.join(choices)}]")
    try:
        ans = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        _status("+", "No input — using auto-detected OS")
        return specific_os

    if not ans or ans.lower() in ("y", "yes"):
        return specific_os

    ans_norm = ans.strip()
    for c in choices:
        if ans_norm.lower() == c.lower():
            _status("+", f"OS overridden to: {c}")
            return c

    _status("~", f"Unrecognised OS '{ans_norm}' — using auto-detected: {specific_os}")
    return specific_os


def _run_checksec(path: str, info: BinaryInfo) -> dict:
    mitigations = {"nx": True, "canary": False, "pie": False,
                   "relro": "no", "fortify": False, "file": path}
    if not _tool_available("checksec"):
        _status("~", "[TOOL_MISSING] checksec not found — skipping mitigation check")
        return mitigations

    out, _ = _run(["checksec", "--file=" + path, "--output=json"])
    if out.startswith("["):
        try:
            data = json.loads(out)
            if isinstance(data, list) and data:
                data = data[0]
            mitigations["nx"]      = data.get("nx", {}).get("found", True)
            mitigations["canary"]  = data.get("canary", {}).get("found", False)
            mitigations["pie"]     = data.get("pie", {}).get("found", False)
            mitigations["relro"]   = data.get("relro", {}).get("description", "no").lower()
            mitigations["fortify"] = data.get("fortify_source", {}).get("found", False)
            return mitigations
        except Exception:
            pass

    # Fallback: plain text parse
    out2, _ = _run(["checksec", "--file=" + path])
    if "NX enabled" in out2:
        mitigations["nx"] = True
    elif "NX disabled" in out2:
        mitigations["nx"] = False
    if "Canary found" in out2:
        mitigations["canary"] = True
    if "PIE enabled" in out2:
        mitigations["pie"] = True
    if "Full RELRO" in out2:
        mitigations["relro"] = "full"
    elif "Partial RELRO" in out2:
        mitigations["relro"] = "partial"
    if "FORTIFY" in out2:
        mitigations["fortify"] = True
    return mitigations


def _extraction_dir(path: str) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    d = os.path.dirname(os.path.abspath(path))
    target = os.path.join(d if os.access(d, os.W_OK) else os.getcwd(),
                          base + "_extracted")
    os.makedirs(target, exist_ok=True)
    return target


def _find_rootfs(outdir: str) -> str:
    for name in ("squashfs-root", "rootfs", "root", "filesystem"):
        p = os.path.join(outdir, name)
        if os.path.isdir(p):
            return p
    # Walk one level for any directory
    try:
        for entry in os.scandir(outdir):
            if entry.is_dir():
                return entry.path
    except Exception:
        pass
    return outdir if os.path.isdir(outdir) else ""


# ── STAGE 1 — Static Analysis ─────────────────────────────────────────────────

_DANGEROUS_FUNS = [
    "strcpy", "strncpy", "strcat", "strncat", "gets", "sprintf", "vsprintf",
    "scanf", "sscanf", "memcpy", "memmove", "strdup", "realpath", "getwd",
    "mktemp", "tmpnam", "strtok", "alloca",
]

_CRED_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key|"
    r"auth[_-]?key|access[_-]?key)\s*[=:]\s*(\S+)"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def stage1_static(triage: TriageResult, args) -> List[Finding]:
    _section("STAGE 1", "Static Analysis")
    findings: List[Finding] = []
    info = triage.binary_info
    path = info.path

    # 1a — Binwalk entropy / signatures (extraction already done in stage 0)
    _status("*", "1a: Binwalk entropy analysis...")
    bw_out, _ = _run(["binwalk", "--entropy", path], timeout=120)
    _parse_entropy_findings(bw_out, findings)

    # 1b — Strings + credential hunt
    _status("*", "1b: String & credential analysis...")
    strings_data = run_strings(info, min_len=8)
    _parse_string_findings(strings_data, findings, triage)

    # readelf (ELF)
    readelf_data = None
    if info.format == "elf":
        _status("*", "1b: readelf sections/symbols...")
        readelf_data = run_readelf(info)
        _parse_readelf_findings(readelf_data, findings, triage)

    # objdump (ELF)
    if info.format == "elf" and _tool_available("objdump"):
        _status("*", "1b: objdump dangerous patterns...")
        tmp = _write_temp(info.raw_bytes, ".elf")
        try:
            od_out, _ = _run(["objdump", "-d", tmp], timeout=120)
        finally:
            os.unlink(tmp)
        _parse_objdump_findings(od_out, findings, triage)

    # 1c — Radare2 function mapping
    _status("*", "1c: Radare2 function + call graph...")
    mcu = resolve_mcu_or_default(args.controller or "", triage.os_type)
    r2_data = run_radare2(info, mcu=mcu)
    _parse_r2_findings(r2_data, findings, triage)

    # 1d — Mitigation absence escalation
    _status("*", "1d: Mitigation absence → severity escalation...")
    findings = _apply_mitigation_findings(findings, triage.mitigations)
    findings.extend(_mitigation_findings(triage.mitigations))

    # Gap 7: PE-specific mitigation checks via pefile
    if info.format == "pe":
        findings.extend(_pe_mitigation_findings(info, triage.mitigations))

    # 1e — RTOS fingerprint / vector table
    _status("*", "1e: RTOS fingerprint / vector table...")
    _parse_rtos_findings(triage, findings)

    _status("+", f"Stage 1 complete: {len(findings)} static finding(s)")
    return findings


_HIGH_ENTROPY_RE = re.compile(
    r"Rising entropy edge\s*\(0\.\d+\)"
    r"|High entropy data.*?0\.(9[5-9]|[89]\d)\d*"
    r"|ENTROPY.*?0\.(9[5-9]|[89]\d)",
    re.IGNORECASE,
)


def _parse_entropy_findings(out: str, findings: List[Finding]) -> None:
    if not _HIGH_ENTROPY_RE.search(out):
        return
    findings.append(Finding(
        id=_next_id(), stage="static",
        title="High-entropy region detected (likely encrypted or compressed data)",
        cwe="CWE-311", severity="INFO",
        component="binary:entropy",
        evidence=out[:500],
        confirmation="UNVERIFIED",
        runtime_flag="EMULATION_INCOMPLETE",
        runtime_test_hint="Identify encryption key source; attempt decryption before analysis",
    ))


def _parse_string_findings(strings_data: dict, findings: List[Finding],
                            triage: TriageResult) -> None:
    interesting = strings_data.get("interesting", [])
    for s in interesting:
        m = _CRED_RE.search(s)
        if m:
            val = m.group(2) if len(m.groups()) >= 2 else ""
            # Skip obvious config defaults / placeholders — not real credentials
            _non_cred = {"false", "true", "none", "null", "yes", "no", "0", "1",
                         "<password>", "<secret>", "changeme", "placeholder",
                         "your_key_here", "xxxx", "****", "todo"}
            if val.lower() in _non_cred or len(val) < 4:
                continue
            sev = "CRITICAL" if not triage.mitigations.get("pie") else "HIGH"
            f = Finding(
                id=_next_id(), stage="static",
                title=f"Hardcoded credential: {m.group(1)}",
                cwe="CWE-798", severity=sev,
                component="binary:strings",
                evidence=s[:200],
                confirmation="PLAUSIBLE",
                manual_steps=[
                    "Extract strings from binary: strings -n 8 <binary>",
                    f"Search for credential pattern: grep -i '{m.group(1)}'",
                    "Replay extracted credential against target service",
                ],
                runtime_test_hint=f"Replay credential '{m.group(2)[:30]}' against SSH/HTTP/Telnet",
            )
            findings.append(f)
        if any(fn in s for fn in _DANGEROUS_FUNS):
            # Already handled in r2/objdump, skip duplicates
            pass

    # IPs and URLs as INFO
    all_strings = strings_data.get("all_sample", [])
    ips  = [s for s in all_strings if _IP_RE.search(s)]
    urls = [s for s in all_strings if _URL_RE.search(s)]
    if ips:
        findings.append(Finding(
            id=_next_id(), stage="static",
            title="Hardcoded IP addresses found",
            cwe="CWE-1392", severity="LOW",
            component="binary:strings",
            evidence="\n".join(ips[:10]),
            confirmation="PLAUSIBLE",
            manual_steps=["Identify hardcoded IPs for attack surface mapping"],
        ))
    if urls:
        findings.append(Finding(
            id=_next_id(), stage="static",
            title="Hardcoded URLs found",
            cwe="CWE-912", severity="LOW",
            component="binary:strings",
            evidence="\n".join(urls[:10]),
            confirmation="PLAUSIBLE",
        ))


def _parse_readelf_findings(readelf: dict, findings: List[Finding],
                             triage: TriageResult) -> None:
    if not readelf:
        return
    sections = readelf.get("sections", "")
    # Check for executable stack
    if "GNU_STACK" in sections and "RWE" in sections:
        findings.append(Finding(
            id=_next_id(), stage="static",
            title="Executable stack segment (RWE GNU_STACK)",
            cwe="CWE-693", severity="CRITICAL",
            component="binary:elf_headers",
            evidence="GNU_STACK segment is RWE",
            confirmation="PLAUSIBLE",
            manual_steps=["Confirm with: readelf -l <binary> | grep GNU_STACK"],
        ))
    # Check for rwx sections
    for line in sections.splitlines():
        if "RWX" in line or ("WX" in line and "WXA" not in line):
            findings.append(Finding(
                id=_next_id(), stage="static",
                title="RWX memory segment found (code injection possible)",
                cwe="CWE-691", severity="HIGH",
                component="binary:elf_sections",
                evidence=line.strip(),
                confirmation="PLAUSIBLE",
            ))


def _parse_objdump_findings(out: str, findings: List[Finding],
                             triage: TriageResult) -> None:
    mit = triage.mitigations
    for fn in _DANGEROUS_FUNS:
        if f"<{fn}>" in out or f"<{fn}@plt>" in out or f"{fn}@plt" in out:
            sev = "HIGH"
            if not mit.get("canary") and fn in ("strcpy", "gets", "strcat", "sprintf"):
                sev = "CRITICAL"
            findings.append(Finding(
                id=_next_id(), stage="static",
                title=f"Dangerous function in use: {fn}()",
                cwe="CWE-120", severity=sev,
                component=f"binary:plt",
                evidence=f"{fn} referenced in disassembly",
                confirmation="PLAUSIBLE",
                exploit_score=0.5 if not mit.get("canary") else 0.2,
                manual_steps=[
                    f"Locate {fn}() callers: objdump -d <binary> | grep -A5 '{fn}'",
                    "Determine input sources feeding the call",
                    "Check buffer size vs. input length",
                ],
            ))


_R2_NAME_PREFIXES = ("sym.imp.", "sym.", "fcn.", "sub_", "loc.", "reloc.", "dbg.")


def _parse_r2_findings(r2_data: dict, findings: List[Finding],
                        triage: TriageResult) -> None:
    fns = r2_data.get("functions", [])
    for fn_line in fns:
        parts = fn_line.split()
        if not parts:
            continue
        addr = parts[0]
        # A2: extract name token and strip r2 prefixes before matching —
        # avoids "strcpy_safe_wrapper" triggering the "strcpy" check
        fn_name = parts[-1] if len(parts) >= 2 else ""
        stripped = fn_name
        for pfx in _R2_NAME_PREFIXES:
            if stripped.startswith(pfx):
                stripped = stripped[len(pfx):]
                break
        for dfn in _DANGEROUS_FUNS:
            if stripped == dfn:
                findings.append(Finding(
                    id=_next_id(), stage="static",
                    title=f"Dangerous call site: {dfn}() at {addr}",
                    cwe="CWE-120", severity="HIGH",
                    component=f"binary:{addr}",
                    evidence=fn_line.strip(),
                    confirmation="PLAUSIBLE",
                    address=addr,
                    exploit_score=0.4,
                ))

    # Check for network input functions adjacent to dangerous functions
    r2_raw = r2_data.get("raw", "")
    net_fns = ["recv", "recvfrom", "read", "fread", "fgets"]
    has_net = any(nf in r2_raw for nf in net_fns)
    if has_net:
        findings.append(Finding(
            id=_next_id(), stage="static",
            title="Network input function identified — potential remote attack surface",
            cwe="CWE-1284", severity="MEDIUM",
            component="binary:network_input",
            evidence="Network I/O functions detected: " + ", ".join(
                f for f in net_fns if f in r2_raw),
            confirmation="UNVERIFIED",
            runtime_flag="NETWORK_STACK_DIFF",
            runtime_test_hint="Fuzz network input paths with boofuzz or raw socket payloads",
        ))


def _mitigation_findings(mit: dict) -> List[Finding]:
    out = []
    if not mit.get("nx"):
        out.append(Finding(
            id=_next_id(), stage="static",
            title="NX/DEP disabled — code injection directly exploitable",
            cwe="CWE-693", severity="CRITICAL",
            component="binary:mitigations",
            evidence="NX bit disabled: shellcode injection possible in any memory write",
            confirmation="CONFIRMED",
            manual_steps=["Inject shellcode via any write primitive"],
            disposition="RESOLVED",
        ))
    if not mit.get("canary"):
        out.append(Finding(
            id=_next_id(), stage="static",
            title="Stack canary absent — stack overflows directly exploitable",
            cwe="CWE-693", severity="HIGH",
            component="binary:mitigations",
            evidence="No stack canary: ret addr overwrite via stack overflow unchecked",
            confirmation="PLAUSIBLE",
            exploit_score=0.8,
        ))
    if not mit.get("pie"):
        out.append(Finding(
            id=_next_id(), stage="static",
            title="PIE disabled — fixed addresses enable reliable ROP chains",
            cwe="CWE-1049", severity="MEDIUM",
            component="binary:mitigations",
            evidence="Binary not position-independent: gadget addresses are static",
            confirmation="CONFIRMED",
            exploit_score=0.6,
            disposition="RESOLVED",
        ))
    relro = mit.get("relro", "no")
    if relro in ("no", "partial"):
        out.append(Finding(
            id=_next_id(), stage="static",
            title=f"RELRO={relro.upper()} — GOT overwrite viable",
            cwe="CWE-1282", severity="HIGH" if relro == "partial" else "CRITICAL",
            component="binary:mitigations",
            evidence=f"RELRO is {relro}: GOT entries rewritable via any write primitive",
            confirmation="PLAUSIBLE",
            exploit_score=0.7,
        ))
    return out


def _pe_mitigation_findings(info, mit: dict) -> List[Finding]:
    """Gap 7: PE-specific DEP/ASLR/CFG/SafeSEH checks via pefile."""
    results = []
    try:
        import pefile
        pe = pefile.PE(data=info.raw_bytes, fast_load=False)
        ch = pe.OPTIONAL_HEADER.DllCharacteristics

        dep   = bool(ch & 0x0100)   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        aslr  = bool(ch & 0x0040)   # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        cfg   = bool(ch & 0x4000)   # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        seh   = not bool(ch & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH → SafeSEH absent

        if not dep:
            results.append(Finding(
                id=_next_id(), stage="static",
                title="PE: DEP/NX disabled — shellcode injection possible",
                cwe="CWE-693", severity="CRITICAL",
                component="binary:pe_dllcharacteristics",
                evidence="DllCharacteristics: NX_COMPAT bit not set",
                confirmation="CONFIRMED", disposition="RESOLVED",
            ))
        if not aslr:
            results.append(Finding(
                id=_next_id(), stage="static",
                title="PE: ASLR disabled — fixed addresses enable reliable ROP",
                cwe="CWE-1049", severity="HIGH",
                component="binary:pe_dllcharacteristics",
                evidence="DllCharacteristics: DYNAMIC_BASE bit not set",
                confirmation="CONFIRMED",
            ))
        if not cfg:
            results.append(Finding(
                id=_next_id(), stage="static",
                title="PE: Control Flow Guard (CFG) absent",
                cwe="CWE-693", severity="MEDIUM",
                component="binary:pe_dllcharacteristics",
                evidence="DllCharacteristics: GUARD_CF bit not set",
                confirmation="CONFIRMED",
            ))
        if seh:
            results.append(Finding(
                id=_next_id(), stage="static",
                title="PE: SafeSEH not enabled — SEH overwrite exploitable",
                cwe="CWE-693", severity="HIGH",
                component="binary:pe_dllcharacteristics",
                evidence="DllCharacteristics: NO_SEH not set; SafeSEH overwrite viable",
                confirmation="CONFIRMED",
                exploit_score=0.7,
            ))
    except ImportError:
        pass  # pefile not installed — graceful degradation
    except Exception:
        pass
    return results


def _apply_mitigation_findings(findings: List[Finding], mit: dict) -> List[Finding]:
    for f in findings:
        title_lower = f.title.lower()
        if not mit.get("canary") and "overflow" in title_lower:
            f.severity = "CRITICAL"
            f.exploit_score = max(f.exploit_score, 0.9)
        if not mit.get("nx") and ("injection" in title_lower or "shellcode" in title_lower):
            f.severity = "CRITICAL"
        if not mit.get("pie") and "rop" in title_lower:
            f.severity = _escalate(f.severity)
        if mit.get("relro", "no") == "no" and "write" in title_lower:
            f.severity = _escalate(f.severity)
    return findings


def _parse_rtos_findings(triage: TriageResult, findings: List[Finding]) -> None:
    rtos = triage.rtos_info
    if rtos.get("detected"):
        findings.append(Finding(
            id=_next_id(), stage="static",
            title=f"RTOS identified: {rtos['detected']}",
            cwe="", severity="INFO",
            component="binary:rtos",
            evidence=f"Confidence: {rtos.get('confidence', '?')}",
            confirmation="PLAUSIBLE",
        ))
    vt = triage.vector_table
    if vt and "vectors" in vt:
        for v in vt.get("vectors", []):
            if v.get("address") in ("0x00000000", "0x00000001"):
                findings.append(Finding(
                    id=_next_id(), stage="static",
                    title=f"Missing fault handler: {v['name']} points to zero",
                    cwe="CWE-755", severity="MEDIUM",
                    component=f"binary:vector_table[{v['index']}]",
                    evidence=f"{v['name']} = {v['address']}",
                    confirmation="CONFIRMED",
                    runtime_flag="HARDWARE_INTERFACE",
                    runtime_test_hint="Trigger fault condition; verify system halts safely",
                ))


# ── STAGE 2A — Ghidra Reverse Engineering ─────────────────────────────────────

_GHIDRA_SCRIPTS = [
    "ExportDecompiled.py",
    "FindVulnPatterns.py",
    "FindCryptoPatterns.py",
    "FindAuthBypass.py",
    "FindUpdateHandlers.py",
    "MapMMIO.py",
    "RankExploitTargets.py",
]


def stage2a_ghidra(triage: TriageResult, existing_findings: List[Finding],
                   args) -> List[Finding]:
    _section("STAGE 2A", "Ghidra Reverse Engineering")

    ghidra_home = _find_ghidra_home()
    if args.skip_ghidra or not ghidra_home:
        _status("~", "[TOOL_MISSING] Ghidra not found — set GHIDRA_HOME or install to /usr/share/ghidra — skipping Stage 2A")
        return []

    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if not os.path.isfile(headless):
        _status("~", f"[TOOL_MISSING] analyzeHeadless not found at {headless}")
        return []

    scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")
    if not os.path.isdir(scripts_dir):
        _status("!", "ghidra_scripts/ directory not found")
        return []

    ghidra_out = tempfile.mkdtemp(prefix="ghidra_out_")
    ghidra_proj = tempfile.mkdtemp(prefix="ghidra_proj_")
    info = triage.binary_info
    path = info.path

    try:
        proc_spec = _ghidra_processor(triage)
        _status("*", f"Ghidra processor spec: {proc_spec}")
        _status("*", f"Running analyzeHeadless (this may take several minutes)...")

        # Build post-script args — pass output dir to every script
        script_args = []
        for script in _GHIDRA_SCRIPTS:
            script_path = os.path.join(scripts_dir, script)
            if os.path.isfile(script_path):
                script_args += ["-postScript", script, ghidra_out]

        cmd = [
            headless, ghidra_proj, "AgentProject",
            "-import", path,
            "-processor", proc_spec,
            "-scriptPath", scripts_dir,
        ] + script_args + ["-deleteProject"]

        out, rc = _run(cmd, timeout=600)
        if rc != 0 and "ERROR" in out.upper():
            _status("!", f"Ghidra completed with warnings/errors (rc={rc})")

        findings = _parse_ghidra_outputs(ghidra_out, triage)
        _status("+", f"Stage 2A: {len(findings)} Ghidra finding(s)")
        return findings

    finally:
        shutil.rmtree(ghidra_out, ignore_errors=True)
        shutil.rmtree(ghidra_proj, ignore_errors=True)


def _ghidra_processor(triage: TriageResult) -> str:
    arch = triage.arch
    bits = triage.bits
    endian = triage.endian
    e = "LE" if endian == "little" else "BE"

    mapping = {
        ("arm", "16"): f"ARM:{e}:32:Cortex",
        ("arm", "32"): f"ARM:{e}:32:default",
        ("arm64", "64"): f"AARCH64:{e}:64:v8A",
        ("arm", "64"):   f"AARCH64:{e}:64:v8A",
        ("mips", "32"): f"MIPS:{e}:32:default",
        ("mips", "64"): f"MIPS:{e}:64:default",
        ("x86", "32"): "x86:LE:32:default",
        ("x86_64", "64"): "x86:LE:64:default",
        ("x86", "64"): "x86:LE:64:default",
        ("riscv", "32"): "RISCV:LE:32:RV32GC",
        ("riscv", "64"): "RISCV:LE:64:RV64GC",
    }
    return mapping.get((arch, bits), f"ARM:{e}:32:default")


def _parse_ghidra_outputs(out_dir: str, triage: TriageResult) -> List[Finding]:
    findings = []
    mit = triage.mitigations

    # Gap 1: Build decompile lookup from ExportDecompiled.json so all other
    # parsers can enrich their findings with full function decompilations.
    _decomp_db: dict = {}
    export_file = os.path.join(out_dir, "ExportDecompiled.json")
    if os.path.isfile(export_file):
        try:
            with open(export_file) as fh:
                exp_data = json.load(fh)
            for fn in exp_data.get("functions", []):
                addr = fn.get("address", "")
                name = fn.get("name", "")
                code = fn.get("decompile", "")
                if addr:
                    _decomp_db[addr] = code
                if name:
                    _decomp_db.setdefault(name, code)
        except Exception:
            pass

    def _enrich_decompile(finding: Finding) -> Finding:
        """Fill ghidra_decompile from ExportDecompiled db if not already set."""
        if not finding.ghidra_decompile:
            code = (_decomp_db.get(finding.address, "")
                    or _decomp_db.get(finding.function_name, ""))
            if code:
                finding.ghidra_decompile = code
        return finding

    # Parse each script's JSON output
    for script in _GHIDRA_SCRIPTS:
        json_file = os.path.join(out_dir, script.replace(".py", ".json"))
        if not os.path.isfile(json_file):
            continue
        try:
            with open(json_file) as fh:
                data = json.load(fh)
        except Exception:
            continue

        if script == "ExportDecompiled.py":
            # Already consumed above into _decomp_db; no separate findings generated.
            pass

        elif script == "FindVulnPatterns.py":
            for item in data.get("findings", []):
                sev = _vuln_severity(item.get("vuln_type", ""), mit)
                f = Finding(
                    id=_next_id(), stage="ghidra",
                    title=item.get("title", f"Vulnerable pattern: {item.get('vuln_type')}"),
                    cwe=item.get("cwe", "CWE-120"),
                    severity=sev,
                    component=f"binary:{item.get('address', '?')}",
                    evidence=item.get("evidence", ""),
                    confirmation="PLAUSIBLE",
                    address=item.get("address", ""),
                    function_name=item.get("function", ""),
                    ghidra_decompile=item.get("decompile", ""),
                    exploit_score=item.get("score", 0.5),
                    manual_steps=[
                        f"Locate function at {item.get('address', '?')} in Ghidra",
                        f"Review decompilation for {item.get('vuln_type')}",
                        "Trace input sources to this call site",
                    ],
                )
                findings.append(_enrich_decompile(f))

        elif script == "FindCryptoPatterns.py":
            for item in data.get("findings", []):
                f = Finding(
                    id=_next_id(), stage="ghidra",
                    title=item.get("title", "Weak/hardcoded crypto pattern"),
                    cwe=item.get("cwe", "CWE-327"),
                    severity=item.get("severity", "HIGH"),
                    component=f"binary:{item.get('address', '?')}",
                    evidence=item.get("evidence", ""),
                    confirmation="PLAUSIBLE",
                    address=item.get("address", ""),
                    function_name=item.get("function", ""),
                    ghidra_decompile=item.get("decompile", ""),
                )
                findings.append(_enrich_decompile(f))

        elif script == "FindAuthBypass.py":
            for item in data.get("findings", []):
                f = Finding(
                    id=_next_id(), stage="ghidra",
                    title=item.get("title", "Auth bypass candidate"),
                    cwe=item.get("cwe", "CWE-287"),
                    severity="HIGH",
                    component=f"binary:{item.get('address', '?')}",
                    evidence=item.get("evidence", ""),
                    confirmation="PLAUSIBLE",
                    address=item.get("address", ""),
                    function_name=item.get("function", ""),
                    ghidra_decompile=item.get("decompile", ""),
                    manual_steps=[
                        f"Patch return value of {item.get('function', '?')} via Frida",
                        "Confirm access to privileged path after bypass",
                    ],
                )
                findings.append(_enrich_decompile(f))

        elif script == "FindUpdateHandlers.py":
            for item in data.get("findings", []):
                f = Finding(
                    id=_next_id(), stage="ghidra",
                    title=item.get("title", "Update/firmware handler: large buffer from external input"),
                    cwe=item.get("cwe", "CWE-20"),
                    severity="HIGH",
                    component=f"binary:{item.get('address', '?')}",
                    evidence=item.get("evidence", ""),
                    confirmation="PLAUSIBLE",
                    address=item.get("address", ""),
                    function_name=item.get("function", ""),
                    ghidra_decompile=item.get("decompile", ""),
                )
                findings.append(_enrich_decompile(f))

        elif script == "MapMMIO.py":
            for item in data.get("mmio_regions", []):
                findings.append(Finding(
                    id=_next_id(), stage="ghidra",
                    title=f"MMIO peripheral reference: {item.get('peripheral', '?')} @ {item.get('address', '?')}",
                    cwe="", severity="INFO",
                    component=f"binary:{item.get('address', '?')}",
                    evidence=item.get("evidence", ""),
                    confirmation="PLAUSIBLE",
                    runtime_flag="HARDWARE_INTERFACE",
                    runtime_test_hint="Verify peripheral behaviour on real hardware",
                ))

        elif script == "RankExploitTargets.py":
            # Priority queue embedded in findings
            for item in data.get("priority_queue", []):
                # Annotate existing ghidra findings with scores if we have addresses
                score = item.get("score", 0)
                addr  = item.get("address", "")
                for f in findings:
                    if f.address == addr:
                        f.exploit_score = max(f.exploit_score, score)

    return findings


def _vuln_severity(vuln_type: str, mit: dict) -> str:
    base = {
        "strcpy": "HIGH", "gets": "CRITICAL", "sprintf": "HIGH",
        "memcpy": "MEDIUM", "scanf": "HIGH", "strcat": "HIGH",
    }.get(vuln_type.lower(), "MEDIUM")
    if not mit.get("canary") and vuln_type in ("strcpy", "gets", "strcat", "sprintf"):
        base = "CRITICAL"
    return base


# ── STAGE 2B — Extracted FS Analysis ─────────────────────────────────────────

def stage2b_filesystem(triage: TriageResult, args) -> List[Finding]:
    _section("STAGE 2B", "Extracted Filesystem Analysis")

    if not triage.has_filesystem or not triage.extracted_path:
        _status("~", "No extracted filesystem — skipping Stage 2B")
        return []

    fs_root = triage.extracted_path
    findings: List[Finding] = []
    _status("*", f"Scanning: {fs_root}")

    # Hardcoded credentials via grep
    _status("*", "Credential hunt (grep)...")
    _grep_credentials(fs_root, findings)

    # SSH / TLS key files
    _status("*", "Key material search...")
    _find_key_files(fs_root, findings)

    # SUID / world-writable
    _status("*", "SUID and world-writable...")
    _find_suid_worldwrite(fs_root, findings)

    # trufflehog
    if _tool_available("trufflehog"):
        _status("*", "trufflehog secret scan...")
        _run_trufflehog(fs_root, findings)
    else:
        _status("~", "[TOOL_MISSING] trufflehog not found")

    # semgrep
    if _tool_available("semgrep"):
        _status("*", "semgrep code analysis...")
        _run_semgrep(fs_root, findings)
    else:
        _status("~", "[TOOL_MISSING] semgrep not found")

    # checksec batch on ELF binaries in extracted FS
    if _tool_available("checksec"):
        _status("*", "checksec batch on extracted ELFs...")
        _batch_checksec(fs_root, findings)

    # searchsploit for version strings
    if _tool_available("searchsploit"):
        _status("*", "searchsploit CVE scan...")
        _run_searchsploit(fs_root, triage, findings)

    _status("+", f"Stage 2B: {len(findings)} filesystem finding(s)")
    return findings


def _grep_credentials(root: str, findings: List[Finding]) -> None:
    patterns = [
        r"password\s*=\s*\S+", r"passwd\s*=\s*\S+",
        r"secret\s*=\s*\S+", r"api_key\s*=\s*\S+",
        r"token\s*=\s*\S+", r"private_key",
    ]
    combined = "|".join(f"({p})" for p in patterns)
    out, _ = _run(
        ["grep", "-rEil", "--include=*.conf", "--include=*.ini",
         "--include=*.cfg", "--include=*.env", "--include=*.sh",
         combined, root],
        timeout=60,
    )
    files = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("[")]
    if files:
        for fp in files[:20]:
            findings.append(Finding(
                id=_next_id(), stage="fs",
                title="Potential credential in config/script file",
                cwe="CWE-312", severity="HIGH",
                component=fp,
                evidence=f"Credential pattern found in: {fp}",
                confirmation="PLAUSIBLE",
                manual_steps=[
                    f"Inspect file: cat {fp}",
                    "Extract credential value and attempt replay",
                ],
            ))


def _find_key_files(root: str, findings: List[Finding]) -> None:
    patterns = ["*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ecdsa",
                "id_ed25519", "authorized_keys", "known_hosts"]
    for pat in patterns:
        out, _ = _run(["find", root, "-name", pat, "-type", "f"], timeout=30)
        for fp in out.splitlines():
            fp = fp.strip()
            if fp:
                findings.append(Finding(
                    id=_next_id(), stage="fs",
                    title=f"Private key / certificate material: {os.path.basename(fp)}",
                    cwe="CWE-321", severity="CRITICAL",
                    component=fp,
                    evidence=f"Key file found: {fp}",
                    confirmation="PLAUSIBLE",
                    manual_steps=[
                        f"Inspect: cat {fp}",
                        "Use key to authenticate against target service",
                    ],
                ))


def _find_suid_worldwrite(root: str, findings: List[Finding]) -> None:
    # SUID binaries
    suid_out, _ = _run(["find", root, "-perm", "-4000", "-type", "f"], timeout=30)
    for fp in suid_out.splitlines():
        fp = fp.strip()
        if fp:
            findings.append(Finding(
                id=_next_id(), stage="fs",
                title=f"SUID binary: {os.path.basename(fp)}",
                cwe="CWE-269", severity="HIGH",
                component=fp,
                evidence=f"SUID set: {fp}",
                confirmation="PLAUSIBLE",
                manual_steps=[
                    f"Inspect binary: file {fp}",
                    "Test for privilege escalation vectors",
                ],
                runtime_flag="HARDWARE_INTERFACE",
                runtime_test_hint="Run SUID binary on device and attempt privilege escalation",
            ))
    # Gap 14: Setuid scripts (-perm -4100)
    suid_script_out, _ = _run(["find", root, "-perm", "-4100", "-not", "-perm", "-4000", "-type", "f"], timeout=30)
    for fp in suid_script_out.splitlines():
        fp = fp.strip()
        if fp:
            findings.append(Finding(
                id=_next_id(), stage="fs",
                title=f"Setuid script (shell injection risk): {os.path.basename(fp)}",
                cwe="CWE-269", severity="HIGH",
                component=fp,
                evidence=f"Script has setuid bit: {fp}",
                confirmation="PLAUSIBLE",
                manual_steps=[
                    f"Inspect script: cat {fp}",
                    "Check for unquoted variables or command injection vectors",
                ],
                runtime_test_hint="Run setuid script with crafted input on device",
            ))

    # World-writable files
    ww_out, _ = _run(["find", root, "-perm", "-o+w", "-not", "-type", "d"], timeout=30)
    for fp in ww_out.splitlines():
        fp = fp.strip()
        if fp:
            findings.append(Finding(
                id=_next_id(), stage="fs",
                title=f"World-writable file: {os.path.relpath(fp, root)}",
                cwe="CWE-732", severity="MEDIUM",
                component=fp,
                evidence=f"o+w permission on: {fp}",
                confirmation="PLAUSIBLE",
            ))


def _run_trufflehog(root: str, findings: List[Finding]) -> None:
    out, rc = _run(["trufflehog", "filesystem", root, "--json", "--no-update"],
                   timeout=120)
    for line in out.splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            item = json.loads(line)
            det = item.get("DetectorName", "")
            raw = item.get("Raw", "")[:100]
            src = item.get("SourceMetadata", {}).get("Data", {})
            fp  = src.get("Filesystem", {}).get("file", "?")
            findings.append(Finding(
                id=_next_id(), stage="fs",
                title=f"Secret detected by trufflehog: {det}",
                cwe="CWE-312", severity="CRITICAL",
                component=fp,
                evidence=f"Detector={det}  Raw={raw}",
                confirmation="PLAUSIBLE",
                manual_steps=[
                    f"Inspect file: {fp}",
                    "Extract secret and attempt replay against target service",
                ],
            ))
        except Exception:
            pass


def _run_semgrep(root: str, findings: List[Finding]) -> None:
    out, rc = _run(["semgrep", "--config=auto", "--json", root], timeout=180)
    try:
        data = json.loads(out)
        for result in data.get("results", []):
            sev = result.get("extra", {}).get("severity", "WARNING")
            sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            findings.append(Finding(
                id=_next_id(), stage="fs",
                title=result.get("check_id", "Semgrep finding"),
                cwe="CWE-703", severity=sev_map.get(sev, "MEDIUM"),
                component=result.get("path", "?") + f":{result.get('start', {}).get('line', '')}",
                evidence=result.get("extra", {}).get("message", "")[:300],
                confirmation="PLAUSIBLE",
            ))
    except Exception:
        pass


def _batch_checksec(root: str, findings: List[Finding]) -> None:
    find_out, _ = _run(["find", root, "-type", "f", "-executable"], timeout=30)
    elfs = []
    for fp in find_out.splitlines():
        fp = fp.strip()
        if fp and os.path.isfile(fp):
            with open(fp, "rb") as fh:
                magic = fh.read(4)
            if magic == b"\x7fELF":
                elfs.append(fp)

    no_nx = []
    for elf in elfs[:50]:
        cs_out, _ = _run(["checksec", "--file=" + elf], timeout=15)
        if "NX disabled" in cs_out or "No canary" in cs_out:
            no_nx.append(os.path.basename(elf))

    if no_nx:
        findings.append(Finding(
            id=_next_id(), stage="fs",
            title=f"Unprotected binaries in filesystem: {', '.join(no_nx[:5])}",
            cwe="CWE-693", severity="HIGH",
            component="fs:binaries",
            evidence=f"Binaries without NX/canary: {no_nx}",
            confirmation="PLAUSIBLE",
        ))


# A5: blocklist of common non-product tokens that produce false positives
_SS_BLOCKLIST = {
    "the", "for", "from", "port", "via", "over", "into", "per", "out",
    "protocol", "version", "kernel", "module", "package", "driver",
    "type", "mode", "level", "size", "length", "count", "number", "value",
    "error", "result", "status", "code", "data", "file", "path", "addr",
    "address", "flag", "bit", "byte", "sec", "max", "min", "num", "buf",
    "header", "frame", "field", "entry", "block", "chunk", "offset",
}

# A5: tighter regex — product name ≥ 4 chars, strict version format
_SS_VER_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_-]{3,19})\s+v?(\d+\.\d+(?:\.\d+)*)\b")


def _run_searchsploit(root: str, triage: TriageResult, findings: List[Finding]) -> None:
    info = triage.binary_info
    strings_out, _ = _run(["strings", "-n", "6", info.path], timeout=30)
    seen: set = set()
    query_count = 0
    for line in strings_out.splitlines():
        m = _SS_VER_RE.search(line)
        if not m:
            continue
        product = m.group(1)
        if product.lower() in _SS_BLOCKLIST:
            continue
        term = f"{product} {m.group(2)}"
        if term in seen or query_count >= 15:
            continue
        seen.add(term)
        query_count += 1
        ss_out, _ = _run(["searchsploit", term, "--json"], timeout=30)
        try:
            data = json.loads(ss_out)
            for exp in data.get("RESULTS_EXPLOIT", [])[:3]:
                findings.append(Finding(
                    id=_next_id(), stage="fs",
                    title=f"Known CVE: {exp.get('Title', '?')}",
                    cwe="CWE-1395", severity="HIGH",
                    component=f"binary:version:{term}",
                    evidence=f"searchsploit: {exp.get('Path', '?')}",
                    confirmation="PLAUSIBLE",
                    manual_steps=[
                        f"searchsploit -x {exp.get('Path', '?')}",
                        "Review exploit and adapt for target environment",
                    ],
                ))
        except Exception:
            pass


# ── STAGE 3 — Dynamic Analysis & Active Exploitation ─────────────────────────

def stage3_dynamic(triage: TriageResult, findings: List[Finding], args) -> List[Finding]:
    _section("STAGE 3", "Dynamic Analysis & Active Exploitation")

    if args.skip_dynamic or args.skip_emulation:
        _status("~", "Dynamic analysis skipped (--skip-dynamic / --skip-emulation)")
        return []

    from emulation.qemu_runner import run_qemu_user, run_qemu_system
    from emulation.unicorn_runner import run_unicorn
    from emulation.gdb_runner import run_gdb_cyclic

    dynamic_findings: List[Finding] = []

    # Sort candidates by exploit score (highest first)
    candidates = sorted(
        [f for f in findings if f.exploit_score > 0.3],
        key=lambda x: x.exploit_score, reverse=True,
    )
    _status("*", f"Dynamic exploitation candidates: {len(candidates)}")

    info = triage.binary_info
    path = info.path
    qemu_bin = _qemu_binary(triage)

    # 3a — QEMU user-mode
    if qemu_bin and _tool_available(qemu_bin):
        _status("*", f"3a: QEMU user-mode ({qemu_bin})...")
        for candidate in candidates[:10]:
            df = run_qemu_user(path, candidate, triage, qemu_bin, timeout=60)
            if df:
                dynamic_findings.extend(df)
    else:
        _status("~", f"[TOOL_MISSING] {qemu_bin} not available — skipping QEMU user-mode")

    # 3b — QEMU system-mode (Linux firmware images with extracted FS)
    if triage.has_filesystem and triage.os_type == "Linux":
        qemu_sys = _qemu_system_binary(triage)
        if qemu_sys and _tool_available(qemu_sys):
            _status("*", f"3b: QEMU system-mode ({qemu_sys})...")
            df = run_qemu_system(path, triage, candidates, timeout=180)
            if df:
                dynamic_findings.extend(df)
        else:
            _status("~", f"[TOOL_MISSING] {qemu_sys} — skipping QEMU system-mode")

    # 3d — Frida auth bypass + crypto key dump (attached to live QEMU process)
    if _tool_available("frida"):
        _status("*", "3d: Frida auth-bypass + crypto key hook...")
        qemu_proc = _start_qemu_background(path, qemu_bin, triage) if qemu_bin else None
        try:
            if dynamic_findings:
                _frida_auth_bypass(triage, findings, dynamic_findings, qemu_proc)
            _frida_crypto_keydump(triage, findings, dynamic_findings, qemu_proc)
        finally:
            if qemu_proc:
                _stop_qemu(qemu_proc)

    # 3e — GDB cyclic offset refinement
    if _tool_available("gdb-multiarch"):
        _status("*", "3e: GDB cyclic offset refinement...")
        for df in [f for f in dynamic_findings if f.confirmation == "PLAUSIBLE"][:5]:
            refined = run_gdb_cyclic(path, df, triage, timeout=60)
            if refined:
                df.emulation_trace += f"\n[GDB] {refined}"
                df.exploit_score = min(df.exploit_score + 0.2, 1.0)
    else:
        _status("~", "[TOOL_MISSING] gdb-multiarch not found")

    _status("+", f"Stage 3: {len(dynamic_findings)} dynamic finding(s)")
    return dynamic_findings


def _qemu_binary(triage: TriageResult) -> str:
    mapping = {
        "arm": "qemu-arm", "arm64": "qemu-aarch64",
        "mips": "qemu-mips", "mips64": "qemu-mips64",
        "x86": "qemu-i386", "x86_64": "qemu-x86_64",
        "riscv": "qemu-riscv32",
    }
    return mapping.get(triage.arch, "qemu-arm")


def _qemu_system_binary(triage: TriageResult) -> str:
    mapping = {
        "arm": "qemu-system-arm", "arm64": "qemu-system-aarch64",
        "mips": "qemu-system-mips", "x86_64": "qemu-system-x86_64",
    }
    return mapping.get(triage.arch, "qemu-system-arm")


def _start_qemu_background(path: str, qemu_bin: str, triage: TriageResult):
    """
    Launch QEMU user-mode in background for Frida to attach to.
    Only works for ELF binaries. Returns Popen on success, None otherwise.
    """
    if triage.format.lower() != "elf":
        return None
    rootfs = getattr(triage, "rootfs_path", None)
    if rootfs and os.path.isdir(rootfs):
        cmd = [qemu_bin, "-L", rootfs, path]
    else:
        cmd = [qemu_bin, path]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
    except Exception as exc:
        _status("~", f"  QEMU background start failed: {exc}")
        return None
    time.sleep(1.5)
    if proc.poll() is not None:
        _status("~", f"  QEMU exited immediately (code {proc.returncode}) — Frida script-only mode")
        return None
    _status("+", f"  QEMU background running (PID {proc.pid})")
    return proc


def _stop_qemu(proc) -> None:
    """Terminate the background QEMU process group."""
    import signal as _signal
    try:
        os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
    except Exception:
        pass
    try:
        proc.wait(timeout=3)
    except Exception:
        pass


def _frida_run_script(pid: int, script: str, timeout: int = 15) -> str:
    """
    Attach Frida to a running PID and execute script.
    Returns combined stdout+stderr from frida CLI.
    """
    try:
        result = subprocess.run(
            ["frida", "-p", str(pid), "--no-pause", "-e", script,
             "--timeout", str(timeout)],
            capture_output=True, timeout=timeout + 5, text=True,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[frida-timeout]"
    except Exception as exc:
        return f"[frida error: {exc}]"


def _frida_auth_bypass(triage: TriageResult, all_findings: List[Finding],
                        dynamic_findings: List[Finding],
                        qemu_proc=None) -> None:
    auth_candidates = [
        f for f in all_findings
        if "auth" in f.title.lower() or "bypass" in f.title.lower()
        if f.address
    ]
    for f in auth_candidates[:3]:
        frida_script = textwrap.dedent(f"""
            Interceptor.attach(ptr('{f.address}'), {{
                onLeave: function(retval) {{
                    console.log('[frida] {f.function_name} original return: ' + retval);
                    retval.replace(1);
                    console.log('[frida] {f.function_name} patched to return 1');
                }}
            }});
        """).strip()

        confirmation = "PLAUSIBLE"
        evidence = f"Frida intercept at {f.address}: force return=1"

        if qemu_proc and qemu_proc.poll() is None:
            frida_out = _frida_run_script(qemu_proc.pid, frida_script, timeout=15)
            if "[frida]" in frida_out and "patched to return 1" in frida_out:
                confirmation = "CONFIRMED"
                evidence = (f"Frida hook fired on QEMU PID {qemu_proc.pid}: "
                            f"{f.function_name} return patched to 1\n" + frida_out[:300])
            else:
                evidence += (f"\n[Frida ran on PID {qemu_proc.pid} but hook did not fire — "
                             f"{f.function_name} not called during probe window]")

        dynamic_findings.append(Finding(
            id=_next_id(), stage="dynamic",
            title=f"Auth bypass via Frida patch: {f.function_name}",
            cwe="CWE-287", severity="HIGH",
            component=f"binary:{f.address}",
            evidence=evidence,
            confirmation=confirmation,
            poc_script=frida_script,
            manual_steps=[
                f"Start target in QEMU: qemu-{triage.arch} -L <rootfs> ./target",
                "Attach Frida: frida -p <pid> --no-pause -e \"<script>\"",
                "Observe whether privileged path is now accessible",
            ],
            runtime_test_hint=f"Attach Frida to live device process, patch {f.function_name} return to 1",
        ))


def _frida_crypto_keydump(triage: TriageResult, all_findings: List[Finding],
                           dynamic_findings: List[Finding],
                           qemu_proc=None) -> None:
    """Hook crypto functions at runtime to dump key material."""
    crypto_candidates = [
        f for f in all_findings
        if any(k in f.title.lower() for k in ["crypto", "aes", "md5", "sha", "rsa",
                                                "encrypt", "decrypt", "cipher", "hmac"])
        if f.address
    ]
    if not crypto_candidates:
        return

    frida_script = textwrap.dedent("""
        // Crypto key material dump — hooks common crypto primitives
        const targets = [
            { name: "AES_set_encrypt_key", keyArg: 0, keyLenArg: 1 },
            { name: "EVP_EncryptInit_ex",  keyArg: 3, keyLenArg: -1 },
            { name: "mbedtls_aes_setkey_enc", keyArg: 1, keyLenArg: 2 },
        ];
        targets.forEach(function(t) {
            var sym = Module.findExportByName(null, t.name);
            if (!sym) return;
            Interceptor.attach(sym, {
                onEnter: function(args) {
                    var keyLen = t.keyLenArg >= 0 ? args[t.keyLenArg].toInt32() / 8 : 32;
                    try {
                        var key = Memory.readByteArray(args[t.keyArg], keyLen);
                        console.log("[frida-keydump] " + t.name + " key: " +
                            Array.from(new Uint8Array(key))
                                .map(b => b.toString(16).padStart(2,'0')).join(''));
                    } catch(e) { console.log("[frida-keydump] read error: " + e); }
                }
            });
            console.log("[frida-keydump] hooked: " + t.name);
        });
    """).strip()

    confirmation = "PLAUSIBLE"
    title = "Frida crypto key dump script generated (attach manually to running process)"
    evidence = ("Hooks AES_set_encrypt_key / EVP_EncryptInit_ex / mbedtls_aes_setkey_enc "
                "to dump key material at runtime")

    if qemu_proc and qemu_proc.poll() is None:
        frida_out = _frida_run_script(qemu_proc.pid, frida_script, timeout=20)
        key_lines = [ln for ln in frida_out.splitlines()
                     if "[frida-keydump]" in ln and "key:" in ln]
        if key_lines:
            confirmation = "CONFIRMED"
            title = "Frida crypto key dump: key material captured from QEMU process"
            evidence = "Key material dumped at runtime:\n" + "\n".join(key_lines[:5])
        elif "[frida-keydump] hooked:" in frida_out:
            title = "Frida crypto key dump: hooks installed, no key observed during probe window"
            evidence += (f"\nFrida ran on PID {qemu_proc.pid}: hooks attached but "
                         f"crypto functions not called during 20s probe window")
        else:
            evidence += (f"\n[Frida ran on PID {qemu_proc.pid} but no hooks fired — "
                         f"possibly no matching crypto exports in process memory]")

    dynamic_findings.append(Finding(
        id=_next_id(), stage="dynamic",
        title=title,
        cwe="CWE-321", severity="HIGH",
        component="binary:crypto_functions",
        evidence=evidence,
        confirmation=confirmation,
        poc_script=frida_script,
        manual_steps=[
            f"Start target: qemu-{triage.arch} -L <rootfs> ./target",
            "Attach Frida: frida -p <pid> --no-pause -e \"<script>\"",
            "Trigger crypto operation in target (e.g. TLS handshake, firmware decrypt)",
            "Observe key bytes in Frida console output",
        ],
        runtime_test_hint="Attach Frida to live device process; trigger crypto path to dump runtime key material",
    ))


# ── STAGE 4 — Exploitation Lab ────────────────────────────────────────────────

def _refine_fuzz_crashes(crash_findings: List[Finding], triage: TriageResult) -> None:
    """Gap 8: Feed fuzz crash Findings back through QEMU cyclic to extract offsets."""
    from emulation.qemu_runner import run_qemu_user
    from emulation.gdb_runner import run_gdb_cyclic

    qemu_bin = {
        "arm": "qemu-arm", "arm64": "qemu-aarch64", "mips": "qemu-mips",
        "x86": "qemu-i386", "x86_64": "qemu-x86_64",
    }.get(triage.arch, "qemu-arm")

    if not _tool_available(qemu_bin):
        return

    for f in crash_findings:
        if f.confirmation not in ("PLAUSIBLE", "UNVERIFIED"):
            continue
        qemu_results = run_qemu_user(
            triage.binary_info.path, f, triage, qemu_bin, timeout=30
        )
        for r in qemu_results:
            if r.confirmation == "CONFIRMED":
                f.confirmation = "CONFIRMED"
                f.disposition  = "RESOLVED"
                f.emulation_trace += "\n[fuzz-refine] " + r.emulation_trace
                f.exploit_score = max(f.exploit_score, r.exploit_score)
                _status("+", f"Fuzz crash promoted to CONFIRMED: [{f.id}] {f.title}")
                break
        else:
            # Try GDB offset measurement even without full confirmation
            gdb_result = run_gdb_cyclic(
                triage.binary_info.path, f, triage, timeout=30
            )
            if gdb_result:
                f.emulation_trace += "\n[fuzz-refine] " + gdb_result


def stage4_exploitation(triage: TriageResult, findings: List[Finding],
                         out_dir: str, args) -> List[Finding]:
    _section("STAGE 4", "Exploitation Lab — PoC Build & Chain")

    try:
        import pwn  # noqa: F401
    except ImportError:
        _status("~", "[TOOL_MISSING] pwntools not installed — skipping Stage 4")
        _mark_plausible(findings)
        return findings

    from emulation.poc_generator import build_poc
    from emulation.chain_builder import attempt_chains
    from emulation.fuzz_runner import run_fuzzer

    poc_dir = os.path.join(out_dir, "poc")
    os.makedirs(poc_dir, exist_ok=True)

    _status("*", "4a: PoC construction...")
    for f in findings:
        if f.confirmation in ("PLAUSIBLE",) and f.exploit_score >= 0.5:
            poc = build_poc(f, triage, poc_dir)
            if poc:
                f.poc_script = poc.get("script", "")
                f.poc_output = poc.get("output", "")
                if poc.get("confirmed"):
                    f.confirmation = "CONFIRMED"
                    f.disposition  = "RESOLVED"
                    f.severity     = _escalate_confirmed(f.severity, poc)
                    _status("+", f"CONFIRMED: [{f.id}] {f.title}")
                else:
                    _status("~", f"PLAUSIBLE:  [{f.id}] emulation failed to confirm")

                # Write PoC script to poc/<id>.py
                if f.poc_script:
                    poc_path = os.path.join(poc_dir, f"{f.id}.py")
                    with open(poc_path, "w") as fh:
                        fh.write(f.poc_script)

    # 4c — Exploit chaining
    _status("*", "4c: Exploit chain attempts...")
    confirmed = [f for f in findings if f.confirmation == "CONFIRMED"]
    chains = attempt_chains(confirmed, triage, poc_dir)
    findings.extend(chains)

    # 4d — Fuzzing (unattempted surface)
    if _tool_available("boofuzz") or _tool_available("radamsa"):
        _status("*", "4d: Fuzzing pass on unattempted surface...")
        unverified = [f for f in findings if f.confirmation == "UNVERIFIED"]
        fuzz_results = run_fuzzer(unverified, triage, poc_dir)
        # Gap 8: Route fuzz crashes back through QEMU cyclic primitive extraction
        if fuzz_results:
            _status("*", f"4d: Refining {len(fuzz_results)} fuzz crash(es) via QEMU cyclic...")
            _refine_fuzz_crashes(fuzz_results, triage)
        findings.extend(fuzz_results)
    else:
        _status("~", "[TOOL_MISSING] boofuzz/radamsa not available — skipping fuzzing")

    confirmed_count = sum(1 for f in findings if f.confirmation == "CONFIRMED")
    _status("+", f"Stage 4: {confirmed_count} confirmed / {len(findings)} total")
    return findings


def _mark_plausible(findings: List[Finding]) -> None:
    for f in findings:
        if f.confirmation == "UNVERIFIED" and f.exploit_score >= 0.5:
            f.confirmation = "PLAUSIBLE"
            f.runtime_flag = f.runtime_flag or "PLAUSIBLE_UNEMULATED"


def _escalate_confirmed(severity: str, poc: dict) -> str:
    if poc.get("shell"):
        return "CRITICAL"
    if poc.get("controlled_pc"):
        return "CRITICAL"
    if poc.get("info_leak"):
        return _escalate(severity)
    return severity


# ── STAGE 6 — Report Synthesis ────────────────────────────────────────────────

def stage6_report(triage: TriageResult, vuln_list_result: dict,
                   args, out_dir: str) -> None:
    _section("STAGE 6", "Report Synthesis")
    os.makedirs(out_dir, exist_ok=True)

    all_findings = vuln_list_result.get("findings", [])
    section_a    = vuln_list_result.get("resolved", [])
    section_b    = vuln_list_result.get("needs_runtime", [])
    chains       = vuln_list_result.get("chains", [])

    # LLM narrative
    narrative = ""
    if not args.no_llm:
        _status("*", "Calling Claude API for narrative synthesis...")
        narrative = _llm_synthesize(triage, all_findings, section_a, section_b)

    # report.json
    report_json_path = os.path.join(out_dir, "report.json")
    report_json = {
        "meta": {
            "file": triage.binary_info.path,
            "sha256": _sha256(triage.binary_info.path),
            "size_bytes": triage.binary_info.size,
            "format": triage.format,
            "arch": triage.arch,
            "bits": triage.bits,
            "os_type": triage.os_type,
            "mcu": triage.mcu_match,
            "mitigations": triage.mitigations,
        },
        "summary": {
            "confirmed": len(section_a),
            "needs_runtime": len(section_b),
            "total": len(all_findings),
            "risk_rating": _overall_risk(all_findings),
        },
        "findings": [asdict(f) for f in all_findings],
        "chains": chains,
        "narrative": narrative,
    }
    with open(report_json_path, "w") as fh:
        json.dump(report_json, fh, indent=2, default=str)
    _status("+", f"report.json → {report_json_path}")

    # report.html
    report_html_path = os.path.join(out_dir, "report.html")
    html = _build_html(triage, all_findings, section_a, section_b, chains, narrative,
                        report_json)
    with open(report_html_path, "w") as fh:
        fh.write(html)
    _status("+", f"report.html → {report_html_path}")

    # Summary to console
    _print_final_summary(triage, section_a, section_b, out_dir)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _overall_risk(findings: List[Finding]) -> str:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if any(f.severity == sev for f in findings):
            return sev
    return "INFO"


def _llm_synthesize(triage: TriageResult, all_findings: List[Finding],
                     section_a: List[Finding], section_b: List[Finding]) -> str:
    try:
        import anthropic
    except ImportError:
        return "[anthropic package not installed — skipping LLM narrative]"

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "[ANTHROPIC_API_KEY not set — skipping LLM narrative]"

    client = anthropic.Anthropic(api_key=api_key)

    def _summarise_findings(fs):
        return "\n".join(
            f"  [{f.id}] {f.severity} {f.confirmation} — {f.title} ({f.cwe})"
            for f in fs[:30]
        )

    def _decompile_excerpts(fs, max_per=1, max_chars=400):
        lines = []
        for f in fs[:5]:
            if f.ghidra_decompile:
                lines.append(f"  [{f.id}] {f.function_name or f.title}:")
                lines.append("    " + f.ghidra_decompile[:max_chars].replace("\n", "\n    "))
        return "\n".join(lines) if lines else "  (none)"

    def _emulation_excerpts(fs):
        lines = []
        for f in fs[:5]:
            if f.emulation_trace:
                lines.append(f"  [{f.id}]: {f.emulation_trace[:300]}")
        return "\n".join(lines) if lines else "  (none)"

    def _poc_excerpts(fs):
        lines = []
        for f in fs[:3]:
            if f.poc_output:
                lines.append(f"  [{f.id}] {f.title}: {f.poc_output[:200]}")
        return "\n".join(lines) if lines else "  (none)"

    prompt = f"""You are an expert firmware security analyst.
Produce a structured Binary Analysis Report for the following target.

TARGET:
  File     : {os.path.basename(triage.binary_info.path)}
  Format   : {triage.format}
  Arch     : {triage.arch} {triage.bits}-bit ({triage.endian}-endian)
  OS Type  : {triage.os_type}
  MCU      : {triage.mcu_match}
  NX       : {triage.mitigations.get('nx')}
  CANARY   : {triage.mitigations.get('canary')}
  PIE      : {triage.mitigations.get('pie')}
  RELRO    : {triage.mitigations.get('relro')}

CONFIRMED EXPLOITS ({len(section_a)} findings):
{_summarise_findings(section_a)}

NEEDS-RUNTIME ({len(section_b)} findings):
{_summarise_findings(section_b)}

GHIDRA DECOMPILATION EXCERPTS (confirmed findings):
{_decompile_excerpts(section_a)}

EMULATION TRACES (confirmed findings):
{_emulation_excerpts(section_a)}

POC OUTPUTS (confirmed findings):
{_poc_excerpts(section_a)}

Produce:
1. Executive Summary (2–3 sentences: overall risk, highest-impact confirmed findings)
2. Key Attack Surface observations (reference specific function names / addresses from decompile)
3. Critical next steps for the runtime analyst (reference runtime flags and emulation traces)
4. Defensive recommendations (top 3, firmware-specific)

Be precise and technical. Reference specific findings by ID. No generic advice.
"""
    try:
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    except Exception as exc:
        return f"[LLM synthesis failed: {exc}]"


def _build_html(triage: TriageResult, all_findings: List[Finding],
                section_a: List[Finding], section_b: List[Finding],
                chains: list, narrative: str, report_json: dict) -> str:
    risk = report_json["summary"]["risk_rating"]
    risk_color = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00",
                  "MEDIUM": "#fbc02d", "LOW": "#388e3c", "INFO": "#0288d1"}
    sev_badge = {
        "CRITICAL": '<span style="background:#d32f2f;color:#fff;padding:2px 6px;border-radius:3px">CRITICAL</span>',
        "HIGH":     '<span style="background:#f57c00;color:#fff;padding:2px 6px;border-radius:3px">HIGH</span>',
        "MEDIUM":   '<span style="background:#fbc02d;color:#222;padding:2px 6px;border-radius:3px">MEDIUM</span>',
        "LOW":      '<span style="background:#388e3c;color:#fff;padding:2px 6px;border-radius:3px">LOW</span>',
        "INFO":     '<span style="background:#0288d1;color:#fff;padding:2px 6px;border-radius:3px">INFO</span>',
    }
    conf_badge = {
        "CONFIRMED":  '<span style="background:#1b5e20;color:#fff;padding:2px 6px;border-radius:3px">CONFIRMED</span>',
        "PLAUSIBLE":  '<span style="background:#e65100;color:#fff;padding:2px 6px;border-radius:3px">PLAUSIBLE</span>',
        "UNVERIFIED": '<span style="background:#546e7a;color:#fff;padding:2px 6px;border-radius:3px">UNVERIFIED</span>',
    }

    def _finding_block(f: Finding) -> str:
        steps_html = ""
        if f.manual_steps:
            steps_html = "<ol>" + "".join(f"<li><code>{s}</code></li>" for s in f.manual_steps) + "</ol>"
        poc_html = ""
        if f.poc_script:
            poc_html = f"<h4>PoC Script (poc/{f.id}.py)</h4><pre><code>{_html_escape(f.poc_script[:2000])}</code></pre>"
        poc_out_html = ""
        if f.poc_output:
            poc_out_html = f"<h4>Emulation Output</h4><pre><code>{_html_escape(f.poc_output[:1000])}</code></pre>"
        ghidra_html = ""
        if f.ghidra_decompile:
            ghidra_html = f"<h4>Ghidra Decompilation</h4><pre><code>{_html_escape(f.ghidra_decompile[:2000])}</code></pre>"
        rt_html = ""
        if f.runtime_flag:
            rt_html = f"""
            <div style="background:#fff3e0;border-left:4px solid #f57c00;padding:8px;margin:8px 0">
              <b>Runtime Flag:</b> {f.runtime_flag}<br>
              <b>Reason:</b> {_html_escape(f.runtime_test_hint)}
            </div>"""
        return f"""
        <div id="{f.id}" style="border:1px solid #ccc;border-radius:6px;margin:16px 0;padding:16px">
          <h3>[{f.id}] {_html_escape(f.title)}</h3>
          <p>
            {sev_badge.get(f.severity, f.severity)} &nbsp;
            {conf_badge.get(f.confirmation, f.confirmation)} &nbsp;
            <b>CWE:</b> {f.cwe or '—'} &nbsp;
            <b>Component:</b> <code>{_html_escape(f.component)}</code>
          </p>
          <p><b>Evidence:</b> {_html_escape(f.evidence[:400])}</p>
          {steps_html}
          {ghidra_html}
          {poc_html}
          {poc_out_html}
          {rt_html}
        </div>"""

    all_blocks = "".join(_finding_block(f) for f in all_findings)
    a_links = "".join(f'<li><a href="#{f.id}">[{f.id}] {_html_escape(f.title)}</a> '
                       f'— {sev_badge.get(f.severity, f.severity)}</li>' for f in section_a)
    b_links = "".join(f'<li><a href="#{f.id}">[{f.id}] {_html_escape(f.title)}</a> '
                       f'— {sev_badge.get(f.severity, f.severity)} ({f.runtime_flag})</li>'
                       for f in section_b)

    narrative_html = narrative.replace("\n", "<br>") if narrative else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Binary Analysis Report — {os.path.basename(triage.binary_info.path)}</title>
<style>
  body {{ font-family: monospace; max-width: 1100px; margin: auto; padding: 20px; background: #fafafa; }}
  h1 {{ color: {risk_color.get(risk, '#333')}; }}
  pre {{ background: #1e1e1e; color: #d4d4d4; padding: 12px; overflow-x: auto; border-radius: 4px; }}
  code {{ font-family: monospace; font-size: 0.9em; }}
  a {{ color: #1565c0; }}
</style>
</head>
<body>
<h1>Binary Analysis Report</h1>
<h2>Target: {os.path.basename(triage.binary_info.path)}</h2>
<table>
  <tr><td><b>Format</b></td><td>{triage.format}</td></tr>
  <tr><td><b>Arch</b></td><td>{triage.arch} {triage.bits}-bit {triage.endian}-endian</td></tr>
  <tr><td><b>OS Type</b></td><td>{triage.os_type}</td></tr>
  <tr><td><b>MCU</b></td><td>{triage.mcu_match}</td></tr>
  <tr><td><b>Risk Rating</b></td><td>{sev_badge.get(risk, risk)}</td></tr>
  <tr><td><b>Confirmed</b></td><td>{len(section_a)}</td></tr>
  <tr><td><b>Needs Runtime</b></td><td>{len(section_b)}</td></tr>
  <tr><td><b>SHA256</b></td><td><code>{report_json['meta'].get('sha256', '?')}</code></td></tr>
</table>

<h2>Executive Summary</h2>
<div style="background:#e8f5e9;padding:12px;border-radius:6px">{narrative_html}</div>

<h2>Section A — Confirmed Exploits ({len(section_a)})</h2>
<ul>{a_links}</ul>

<h2>Section B — Needs Runtime ({len(section_b)})</h2>
<ul>{b_links}</ul>

<h2>All Findings</h2>
{all_blocks}

{_html_attack_surface(triage, all_findings)}

{_html_appendix(triage)}
</body>
</html>"""


def _html_attack_surface(triage: TriageResult, all_findings: List[Finding]) -> str:
    """Gap 12 Section 5: Attack Surface Map."""
    # Collect MMIO regions from triage RTOS info
    mmio_rows = ""
    rtos = triage.rtos_info or {}
    mmio_list = rtos.get("mmio_regions", [])
    for m in mmio_list[:20]:
        mmio_rows += (
            f"<tr><td><code>{_html_escape(str(m.get('address', '?')))}</code></td>"
            f"<td>{_html_escape(str(m.get('peripheral', '?')))}</td>"
            f"<td>{_html_escape(str(m.get('description', '')))}</td></tr>"
        )
    mmio_table = (
        f"<table><tr><th>Address</th><th>Peripheral</th><th>Description</th></tr>"
        f"{mmio_rows}</table>"
    ) if mmio_rows else "<p><em>No MMIO regions detected</em></p>"

    # Collect unique components from all findings
    components = sorted({f.component for f in all_findings if f.component})
    comp_list = "".join(f"<li><code>{_html_escape(c)}</code></li>" for c in components[:30])

    # Collect ports from dynamic findings
    ports = sorted({
        f.component.split(":")[-1]
        for f in all_findings
        if "network" in f.component.lower() or "http" in f.component.lower()
    })
    port_list = ", ".join(f"<code>{_html_escape(p)}</code>" for p in ports[:20]) or "<em>none detected</em>"

    return f"""
<h2>Section 5 — Attack Surface Map</h2>
<h3>MMIO Regions (Ghidra MapMMIO)</h3>
{mmio_table}
<h3>Open Network Ports (dynamic probe)</h3>
<p>{port_list}</p>
<h3>Vulnerable Components</h3>
<ul>{comp_list}</ul>
"""


def _html_appendix(triage: TriageResult) -> str:
    """Gap 12 Section 6: Appendix — runtime flag legend + tool table."""
    flag_rows = ""
    flags = [
        ("DEEPER_EXPLOIT",       "Confirmed in emulation; real device may yield persistent/higher-impact shell"),
        ("EMULATION_INCOMPLETE", "Hardware peripheral absent in QEMU; repeat with GDB/JTAG on real device"),
        ("HARDWARE_INTERFACE",   "Physical interface (JTAG/UART) required"),
        ("TIMING_DEPENDENT",     "Side-channel or race; measure on real silicon"),
        ("NETWORK_STACK_DIFF",   "QEMU virtio-net may differ from target NIC; repeat with real hardware"),
        ("BOOT_CHAIN",           "Boot-sequence dependent; attach debugger at reset"),
        ("CRYPTO_ACCELERATOR",   "Crypto hardware accelerator absent in QEMU; validate on silicon"),
        ("PLAUSIBLE_UNEMULATED", "No emulation run succeeded; confirm all logic on device"),
    ]
    for flag, desc in flags:
        flag_rows += f"<tr><td><code>{flag}</code></td><td>{_html_escape(desc)}</td></tr>"

    tool_rows = ""
    tools = [
        ("binwalk",       "apt",   "Firmware unpacking + format detection"),
        ("radare2",       "apt",   "Disassembly, CFG, string extraction"),
        ("checksec",      "apt",   "ELF mitigation flags"),
        ("strace",        "apt",   "Syscall tracing during QEMU user-mode run"),
        ("ltrace",        "apt",   "Library call tracing during baseline run"),
        ("gdb-multiarch", "apt",   "Cross-architecture GDB for offset measurement"),
        ("gdbserver",     "apt",   "GDB server for remote attach to QEMU process"),
        ("searchsploit",  "apt",   "CVE lookup for extracted version strings"),
        ("qemu-arm",      "apt",   "ARM user-mode emulation for active exploitation"),
        ("radamsa",       "src",   "File-format mutation fuzzing (needs source build)"),
        ("frida",         "pip",   "Runtime hook for auth bypass + crypto key dump"),
        ("boofuzz",       "pip",   "Network service mutation fuzzing"),
        ("trufflehog",    "pip",   "Secret scanning in extracted filesystem"),
        ("semgrep",       "pip",   "Pattern-based static analysis"),
    ]
    for name, src, desc in tools:
        tool_rows += f"<tr><td><code>{name}</code></td><td>{src}</td><td>{_html_escape(desc)}</td></tr>"

    return f"""
<h2>Section 6 — Appendix</h2>
<h3>Runtime Flag Legend</h3>
<table>
  <tr><th>Flag</th><th>Meaning</th></tr>
  {flag_rows}
</table>
<h3>Tool Dependency Matrix</h3>
<table>
  <tr><th>Tool</th><th>Source</th><th>Used for</th></tr>
  {tool_rows}
</table>
<p><em>re_agent.py v2.0 — agent.md design</em></p>
"""


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _print_final_summary(triage: TriageResult, section_a: List[Finding],
                          section_b: List[Finding], out_dir: str) -> None:
    print(f"\n{'═' * W}")
    print(" BINARY ANALYSIS REPORT — SUMMARY")
    print(f"{'═' * W}")
    print(f" File   : {triage.binary_info.path}")
    print(f" Arch   : {triage.arch} {triage.bits}-bit  OS={triage.os_type}")
    print(f" Risk   : {_overall_risk(section_a + section_b)}")
    print()
    print(f" Section A — CONFIRMED ({len(section_a)} findings):")
    for f in section_a:
        print(f"   [{f.id}] {f.severity:<8} {f.title}")
    print()
    print(f" Section B — NEEDS_RUNTIME ({len(section_b)} findings):")
    for f in section_b:
        print(f"   [{f.id}] {f.severity:<8} {f.title}  [{f.runtime_flag}]")
    print()
    print(f" Output → {out_dir}/")
    print(f"   report.html          — open in browser")
    print(f"   report.json          — machine-readable")
    print(f"   runtime_handoff.json — Runtime Analysis LLM contract")
    print(f"   poc/                 — PoC scripts")
    print(f"{'═' * W}\n")


# ── Gap 3: --exploit-only state loader ───────────────────────────────────────

def _load_exploit_only_state(args, path: str):
    """
    Gap 3: Load saved triage + findings from a prior run so Stages 0-2 can be skipped.
    Reads <out_dir>/report.json for triage context and vuln_list.json for findings.
    Returns (triage, findings) or (None, []) on failure.
    """
    out_dir = os.path.abspath(args.out_dir)
    report_path = os.path.join(out_dir, "report.json")
    vuln_path   = os.path.join(out_dir, "vuln_list.json")

    if not os.path.isfile(report_path):
        print(f"[!] --exploit-only requires {report_path} from a prior run", file=sys.stderr)
        return None, []
    if not os.path.isfile(vuln_path):
        print(f"[!] --exploit-only requires {vuln_path} from a prior run", file=sys.stderr)
        return None, []

    try:
        with open(report_path) as fh:
            rpt = json.load(fh)
        with open(vuln_path) as fh:
            vl = json.load(fh)
    except Exception as exc:
        print(f"[!] Failed to load prior run state: {exc}", file=sys.stderr)
        return None, []

    # Reconstruct minimal TriageResult from report.json meta section
    # report.json schema: {"meta": {"format", "arch", "bits", "os_type", "mcu", ...}}
    meta = rpt.get("meta", {})

    from toolkit.detector import BinaryInfo  # type: ignore
    try:
        binfo = BinaryInfo(path=path, raw_bytes=open(path, "rb").read())
    except Exception:
        binfo = None

    triage = TriageResult(
        format     = meta.get("format", "unknown"),
        arch       = meta.get("arch", args.arch or "arm"),
        bits       = meta.get("bits", "32"),
        endian     = meta.get("endian", args.endian or "little"),
        os_type    = meta.get("os_type", args.os_type or "Unknown"),
        mcu_match  = meta.get("mcu", "unknown"),
        confidence = 1.0,
        load_address  = meta.get("load_address", 0),
        entry_point   = meta.get("entry_point", 0),
        has_filesystem = False,
        extracted_path = None,
        binary_info    = binfo,
        mitigations    = meta.get("mitigations", {}),
        rtos_info      = meta.get("rtos_info", {}),
        vector_table   = [],
    )

    # Reconstruct Finding objects from vuln_list.json
    from dataclasses import fields as _dc_fields
    _finding_field_names = {f.name for f in _dc_fields(Finding)}
    findings: List[Finding] = []
    for item in vl.get("findings", []):
        kwargs = {k: v for k, v in item.items() if k in _finding_field_names}
        findings.append(Finding(**kwargs))

    return triage, findings


# ── VxWorks Pipeline (VX1–VX6) ───────────────────────────────────────────────

_VX_GHIDRA_SCRIPTS = [
    "VxSymbolTableParser.py",
    "FindVxTaskStackVulns.py",
    "FindVxWDBExposure.py",
    "FindVxShellExposure.py",
    "FindVxISRVulns.py",
    "FindVxNetworkHandlers.py",
    "FindVxCryptoWeakness.py",
    "RankVxExploitTargets.py",
]

_VX_PROCESSOR_SPECS = {
    "ppc":    "PowerPC:BE:32:default",
    "mips":   "MIPS:BE:32:default",
    "mips_le":"MIPS:LE:32:default",
    "arm":    "ARM:LE:32:v7",
    "arm_be": "ARM:BE:32:v5T",
    "arm64":  "AARCH64:LE:64:v8A",
    "x86":    "x86:LE:32:default",
    "x86_64": "x86:LE:64:default",
}


def stage_vx1_static(triage: TriageResult, args) -> List[Finding]:
    """
    VX1 — VxWorks Static Analysis
    VX1a: Load address detection
    VX1b: Symbol table extraction (vxhunter / heuristic)
    VX1c: Version fingerprint + URGENT/11 check
    VX1d: No-mitigation declaration (auto-escalate all memory corruption)
    VX1e: Attack surface map (strings / radare2 / WDB port scan)
    VX1f: Radare2 function + call graph
    """
    _section("STAGE VX1", "VxWorks Static Analysis")
    findings: List[Finding] = []
    info   = triage.binary_info
    path   = info.path
    arch   = triage.arch.lower()
    endian = triage.endian.lower()

    # VX1a — load address detection
    _status("*", "VX1a: Load address detection...")
    from vxworks.load_addr import detect_load_address
    load_addr, method = detect_load_address(
        info.raw_bytes, arch,
        endian=triage.endian,
        fallback=getattr(args, "load_addr", 0) or 0
    )
    triage.load_address = load_addr
    _status("+", f"Load address: {load_addr:#x}  (method: {method})")

    # VX1b — symbol table extraction
    out_dir = _extraction_dir(path)
    sym_json = os.path.join(out_dir, "vxworks_symbols.json")
    _status("*", "VX1b: VxWorks symbol table extraction...")
    from vxworks.symbol_parser import extract_symbols, detect_vxworks_version
    sym_result = extract_symbols(path, load_addr, sym_json)
    sym_count  = sym_result.get("symbol_count", 0)
    symbols    = sym_result.get("symbols", []) or sym_result.get(
        "data", {}).get("symbols", [])
    _status("+", f"Symbols: {sym_count}  (source: {sym_result.get('source', '?')})")
    if sym_count == 0:
        findings.append(Finding(
            id=_next_id(), stage="static",
            title="VxWorks symbol table not recoverable",
            cwe="CWE-693", severity="MEDIUM",
            component="binary:vxworks_symbols",
            evidence=f"vxhunter and heuristic both failed.  Load addr: {load_addr:#x}",
            confirmation="CONFIRMED",
            analysis_pipeline="vxworks",
            runtime_test_hint="Try manual vxhunter with different --load-address values",
        ))

    # VX1c — version fingerprint + URGENT/11
    _status("*", "VX1c: VxWorks version fingerprint + URGENT/11 check...")
    vx_version = detect_vxworks_version(info.raw_bytes)
    _status("+", f"VxWorks version class: {vx_version}")
    from vxworks.urgent11 import assess_urgent11
    u11 = assess_urgent11(info.raw_bytes, symbols, host=getattr(args, "target_ip", None))
    if u11.get("ipnet_present"):
        ver_s = u11.get("version_status", "unknown")
        sev   = u11.get("severity", "HIGH")
        findings.append(Finding(
            id=_next_id(), stage="static",
            title=f"URGENT/11: IPNET stack present, version={vx_version} ({ver_s})",
            cwe="CWE-120",
            severity=sev,
            component="binary:ipnet",
            evidence=(f"ipcom_* symbols: {u11['static_finding'].get('ipcom_symbol_count', 0)}  "
                      f"CVSS 9.8 CVEs: CVE-2019-12255/12260/12263"),
            confirmation="PLAUSIBLE",
            analysis_pipeline="vxworks",
            exploit_score=9.8 if ver_s == "vulnerable" else 5.0,
            manual_steps=[
                "Check VxWorks version: strings firmware.bin | grep -i 'version'",
                "If < 6.9.4.1: all 11 URGENT/11 CVEs apply",
                "Run CVE-2019-12255 PoC (TCP URG pointer) against live target",
            ],
            cvss=9.8 if ver_s == "vulnerable" else 7.0,
        ))

    # VX1d — no-mitigation declaration
    _status("*", "VX1d: VxWorks no-mitigation declaration...")
    _status("!", "VxWorks: NO ASLR | NO NX | NO canary (default) — "
                 "all memory corruption auto-escalated to CRITICAL")
    findings.append(Finding(
        id=_next_id(), stage="static",
        title="VxWorks: No ASLR, No NX, No stack canary (all memory corruption = CRITICAL)",
        cwe="CWE-693", severity="CRITICAL",
        component="binary:vxworks_mitigations",
        evidence=(
            "VxWorks default: no ASLR (fixed addresses), no NX (shellcode anywhere), "
            "no stack canary.  Every stack/heap overflow = direct code execution. "
            "Exception: VxWorks 7 RTP mode (rtpCreate) has address-space isolation."
        ),
        confirmation="CONFIRMED",
        disposition="RESOLVED",
        analysis_pipeline="vxworks",
    ))

    # VX1e — attack surface map
    _status("*", "VX1e: Attack surface map (strings + network services)...")
    from toolkit.tools import run_strings
    strings_data = run_strings(info, min_len=8)
    all_strings  = strings_data.get("all_sample", [])

    # Look for service indicators
    service_indicators = {
        "FTP":    ["ftpd", "FTP server", "ftpLogin"],
        "HTTP":   ["httpd", "goahead", "WebServer", "HTTP/1"],
        "Telnet": ["telnetd", "tShell", "VxWorks Shell"],
        "SNMP":   ["snmpd", "snmpInit", "MIB"],
        "WDB":    ["wdbTgtSvr", "wdbInit", "WDB"],
        "SSH":    ["sshd", "SSH-2.0"],
    }
    attack_surface = []
    for svc, markers in service_indicators.items():
        if any(m in s for s in all_strings for m in markers):
            attack_surface.append(svc)
            if svc == "WDB":
                findings.append(Finding(
                    id=_next_id(), stage="static",
                    title="WDB debug service detected (UDP/17185) — unauthenticated memory R/W",
                    cwe="CWE-288", severity="CRITICAL",
                    component="binary:wdb_service",
                    evidence="wdbTgtSvr / wdbInit strings present in binary",
                    confirmation="PLAUSIBLE",
                    analysis_pipeline="vxworks",
                    exploit_score=10.0,
                    manual_steps=[
                        "Probe: python3 -c \"from vxworks.wdb_client import probe_wdb; "
                        "import json; print(json.dumps(probe_wdb('TARGET_IP'), indent=2))\"",
                        "If open: use wdb_client.mem_read/mem_write for full memory control",
                    ],
                ))
            elif svc == "Telnet":
                findings.append(Finding(
                    id=_next_id(), stage="static",
                    title="VxWorks shell service detected (TCP/5001 or Telnet/23) — unauthenticated RCE",
                    cwe="CWE-78", severity="CRITICAL",
                    component="binary:vxworks_shell",
                    evidence="shellInit / tShell strings present in binary",
                    confirmation="PLAUSIBLE",
                    analysis_pipeline="vxworks",
                    exploit_score=10.0,
                    manual_steps=[
                        "Probe: telnet <TARGET_IP> 5001  OR  telnet <TARGET_IP> 23",
                        "If open: run 'i' for task list, 'version' for OS version",
                        "RCE via: sp(func_addr, arg0, arg1)",
                    ],
                ))

    if attack_surface:
        _status("+", f"Attack surface: {', '.join(attack_surface)}")
    else:
        _status("~", "No common service strings found")

    # VX1f — radare2
    _status("*", "VX1f: Radare2 function analysis...")
    from toolkit.mcu import resolve_mcu_or_default
    mcu = resolve_mcu_or_default(getattr(args, "controller", "") or "", "RTOS")
    r2_data = run_radare2(info, mcu=mcu)
    _parse_r2_findings(r2_data, findings, triage)

    # Tag all findings with vxworks pipeline
    for f in findings:
        if not f.analysis_pipeline:
            f.analysis_pipeline = "vxworks"

    _status("+", f"VX1 complete: {len(findings)} finding(s)")
    return findings, symbols, load_addr


def stage_vx2_ghidra(triage: TriageResult, symbols: list,
                     load_addr: int, findings: List[Finding],
                     args) -> List[Finding]:
    """
    VX2A — Ghidra headless analysis with VxWorks scripts
    VX2B — VxWorks filesystem extraction (HRFS / dosFs)
    """
    _section("STAGE VX2", "VxWorks Ghidra RE + Filesystem")
    new_findings: List[Finding] = []
    info = triage.binary_info
    path = info.path
    arch = triage.arch.lower()
    endian = triage.endian.lower()

    if getattr(args, "skip_ghidra", False):
        _status("~", "[SKIP] --skip-ghidra: skipping VX2A")
    else:
        ghidra_home = _find_ghidra_home()
        headless    = os.path.join(ghidra_home, "support", "analyzeHeadless") if ghidra_home else ""
        if not ghidra_home or not os.path.isfile(headless):
            _status("~", "[TOOL_MISSING] Ghidra not found — set GHIDRA_HOME or install to /usr/share/ghidra")
        else:
            out_dir  = _extraction_dir(path)
            ghidra_dir = os.path.join(out_dir, "ghidra_vxworks_project")
            os.makedirs(ghidra_dir, exist_ok=True)
            sym_json = os.path.join(out_dir, "vxworks_symbols.json")

            # Determine processor spec
            endian_key = arch if endian != "big" else arch + "_be"
            proc_spec  = _VX_PROCESSOR_SPECS.get(
                endian_key, _VX_PROCESSOR_SPECS.get(arch, "ARM:LE:32:v7"))

            _status("*", f"VX2A: Ghidra headless ({proc_spec}, load={load_addr:#x})...")
            scripts_dir = os.path.join(os.path.dirname(__file__),
                                       "ghidra_scripts_vxworks")
            # vxhunter_ghidra.py must run FIRST (name annotation inside Ghidra)
            # then VxSymbolTableParser.py and the rest
            vxhunter_script = os.path.join(scripts_dir, "vxhunter_ghidra.py")
            post_scripts = []
            if os.path.isfile(vxhunter_script):
                post_scripts += ["-postScript", "vxhunter_ghidra.py", out_dir]
            for script in _VX_GHIDRA_SCRIPTS:
                script_path = os.path.join(scripts_dir, script)
                if os.path.isfile(script_path):
                    post_scripts += ["-postScript", script, out_dir, sym_json]

            cmd = [
                headless, ghidra_dir, "ProjectVxWorks",
                "-import", path,
                "-processor", proc_spec,
                "-loader", "BinaryLoader",
                "-loader-baseAddr", hex(load_addr),
            ] + post_scripts + [
                "-scriptPath", scripts_dir,
                "-deleteProject",
            ]
            ghidra_out, rc = _run(cmd, timeout=600)
            if rc != 0:
                _status("~", f"[GHIDRA] exit {rc} — see output below")
                _status("~", ghidra_out[-500:])
            else:
                _status("+", "Ghidra VxWorks analysis complete")

            # Parse all VxWorks script JSON outputs
            new_findings.extend(_parse_vx_ghidra_outputs(out_dir))

    # VX2B — VxWorks filesystem extraction
    _status("*", "VX2B: VxWorks filesystem extraction (HRFS/dosFs)...")
    out_dir = _extraction_dir(path)
    try:
        from vxworks.hrfs_extract import extract_vxworks_filesystems
        vxfs_result = extract_vxworks_filesystems(path, os.path.join(out_dir, "vxworks_fs"))
        n_found = vxfs_result.get("filesystems_found", 0)
        if n_found > 0:
            _status("+", f"VxWorks FS: {n_found} filesystem(s) found")
        else:
            _status("~", "No VxWorks-specific filesystems (HRFS/dosFs) found")
    except Exception as exc:
        _status("~", f"VxWorks FS extraction error: {exc}")

    for f in new_findings:
        if not f.analysis_pipeline:
            f.analysis_pipeline = "vxworks"

    _status("+", f"VX2 complete: {len(new_findings)} new finding(s)")
    return new_findings


def _parse_vx_ghidra_outputs(out_dir: str) -> List[Finding]:
    """Parse all VxWorks Ghidra script JSON outputs into Finding objects."""
    findings: List[Finding] = []

    script_map = {
        "vxworks_stack_vulns.json":    _parse_vx_stack_vulns,
        "vxworks_wdb_exposure.json":   _parse_vx_generic_findings,
        "vxworks_shell_exposure.json": _parse_vx_generic_findings,
        "vxworks_isr_vulns.json":      _parse_vx_generic_findings,
        "vxworks_network_handlers.json": _parse_vx_network_findings,
        "vxworks_crypto_weakness.json":  _parse_vx_generic_findings,
        "vxworks_ranked_targets.json":   None,   # consumed for exploit_score only
    }

    for fname, parser in script_map.items():
        fpath = os.path.join(out_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception:
            continue
        if parser:
            findings.extend(parser(data))

    # Pull exploit_score updates from ranked targets
    ranked_path = os.path.join(out_dir, "vxworks_ranked_targets.json")
    if os.path.isfile(ranked_path):
        try:
            with open(ranked_path) as f:
                ranked = json.load(f)
            score_map = {
                item.get("address", ""): item.get("exploit_score", 0.0)
                for item in ranked.get("priority_queue", [])
            }
            for f in findings:
                if f.address in score_map:
                    f.exploit_score = max(f.exploit_score, score_map[f.address])
        except Exception:
            pass

    return findings


def _parse_vx_stack_vulns(data: dict) -> List[Finding]:
    out = []
    for item in data.get("findings", []):
        out.append(Finding(
            id=_next_id(), stage="ghidra",
            title=f"VxWorks: {item.get('callee', '?')}() call in {item.get('caller', '?')}",
            cwe=item.get("cwe", "CWE-120"),
            severity=item.get("severity", "CRITICAL"),
            component=f"binary:{item.get('caller_addr', '?')}",
            evidence=(f"call site: {item.get('call_site', '?')}  "
                      f"callee: {item.get('callee', '?')}"),
            confirmation="PLAUSIBLE",
            address=item.get("caller_addr", ""),
            function_name=item.get("caller", ""),
            analysis_pipeline="vxworks",
            exploit_score=8.0,
            manual_steps=[
                f"Locate {item.get('callee','?')}() call at {item.get('call_site','?')} in Ghidra",
                "Trace input to determine if attacker-controlled",
                "VxWorks: no canary — overwrite saved LR/RA directly",
            ],
        ))
    return out


def _parse_vx_network_findings(data: dict) -> List[Finding]:
    out = []
    for item in data.get("findings", []):
        sev = item.get("severity", "HIGH")
        out.append(Finding(
            id=_next_id(), stage="ghidra",
            title=f"VxWorks network handler: {item.get('function', '?')} — {item.get('type', '?')}",
            cwe=item.get("cwe", "CWE-120"),
            severity=sev,
            component=f"binary:{item.get('address', '?')}",
            evidence=item.get("note", ""),
            confirmation="PLAUSIBLE",
            address=item.get("address", ""),
            function_name=item.get("function", ""),
            analysis_pipeline="vxworks",
            exploit_score=9.0 if sev == "CRITICAL" else 7.0,
            runtime_flag="NETWORK_STACK_DIFF",
            runtime_test_hint="Fuzz this handler with vx_fuzz_runner.fuzz_all_services()",
        ))
    return out


def _parse_vx_generic_findings(data: dict) -> List[Finding]:
    out = []
    for item in data.get("findings", []):
        sev = item.get("severity", "MEDIUM")
        out.append(Finding(
            id=_next_id(), stage="ghidra",
            title=f"VxWorks: {item.get('type', '?')} — {item.get('note', '')[:80]}",
            cwe=item.get("cwe", "CWE-693"),
            severity=sev,
            component=f"binary:{item.get('address', '?')}",
            evidence=item.get("note", item.get("string", "")),
            confirmation="PLAUSIBLE",
            address=item.get("address", ""),
            analysis_pipeline="vxworks",
            exploit_score=6.0 if sev == "HIGH" else 3.0,
        ))
    return out


def stage_vx3_dynamic(triage: TriageResult, findings: List[Finding],
                      args) -> List[Finding]:
    """
    VX3 — VxWorks Dynamic Analysis
    VX3a: QEMU system-mode emulation (graceful fallback on BSP failure)
    VX3b: Unicorn emulation with VxWorks API stubs
    VX3c: WDB live probe (if --target-ip set)
    VX3d: VxWorks shell recon (if --target-ip set)
    VX3e: Fuzzing (boofuzz / radamsa)
    """
    _section("STAGE VX3", "VxWorks Dynamic Analysis")
    new_findings: List[Finding] = []
    info     = triage.binary_info
    path     = info.path
    arch     = triage.arch.lower()
    out_dir  = _extraction_dir(path)
    load_addr = triage.load_address

    target_ip = getattr(args, "target_ip", None)

    if getattr(args, "skip_emulation", False) or getattr(args, "skip_dynamic", False):
        _status("~", "[SKIP] --skip-emulation: skipping VX3")
        return new_findings

    # VX3a — QEMU system-mode
    if not getattr(args, "skip_qemu_vxworks", False):
        _status("*", "VX3a: QEMU system-mode emulation attempt...")
        qemu_map = {
            "ppc":  ("qemu-system-ppc",  "ppce500"),
            "mips": ("qemu-system-mips", "malta"),
            "arm":  ("qemu-system-arm",  "versatilepb"),
            "x86":  ("qemu-system-i386", "pc"),
        }
        qemu_bin, machine = qemu_map.get(arch, ("qemu-system-arm", "versatilepb"))
        if _tool_available(qemu_bin):
            qemu_cmd = [
                qemu_bin, "-M", machine, "-nographic",
                "-device", f"loader,file={path},addr={load_addr:#x}",
                "-serial", "stdio",
            ]
            _status("*", f"Running: {' '.join(qemu_cmd[:4])} ... (60s timeout)")
            qemu_out, rc = _run(qemu_cmd, timeout=60)
            if "VxWorks" in qemu_out or "usrRoot" in qemu_out:
                _status("+", "QEMU: VxWorks boot strings detected — partial boot!")
                new_findings.append(Finding(
                    id=_next_id(), stage="dynamic",
                    title="VxWorks partial QEMU boot — kernel entry confirmed",
                    cwe="CWE-693", severity="INFO",
                    component="binary:qemu",
                    evidence=qemu_out[:500],
                    confirmation="CONFIRMED",
                    analysis_pipeline="vxworks",
                    emulation_trace=qemu_out[:1000],
                ))
            else:
                _status("~", "QEMU: No VxWorks boot strings — BSP mismatch (expected)")
        else:
            _status("~", f"[TOOL_MISSING] {qemu_bin} not found")
    else:
        _status("~", "[SKIP] --skip-qemu-vxworks: skipping QEMU")

    # VX3b — Unicorn emulation
    _status("*", "VX3b: Unicorn emulation with VxWorks API stubs...")
    try:
        from vxworks.vx_unicorn_runner import VxWorksUnicornRunner
        sym_json = os.path.join(out_dir, "vxworks_symbols.json")
        symbols_list = []
        if os.path.isfile(sym_json):
            with open(sym_json) as f:
                sym_data = json.load(f)
            symbols_list = sym_data.get("symbols", []) or sym_data.get(
                "data", {}).get("symbols", [])

        runner = VxWorksUnicornRunner(
            path, load_addr, arch=arch, symbols=symbols_list)

        # Find high-scoring functions from ranked targets to emulate
        ranked_path = os.path.join(out_dir, "vxworks_ranked_targets.json")
        target_funcs = []
        if os.path.isfile(ranked_path):
            with open(ranked_path) as f:
                ranked = json.load(f)
            for item in ranked.get("priority_queue", [])[:5]:
                addr_s = item.get("address", "")
                if addr_s:
                    try:
                        target_funcs.append(int(addr_s, 16))
                    except ValueError:
                        pass

        for func_addr in target_funcs[:3]:
            _status("*", f"  Emulating function at {func_addr:#x}...")
            try:
                from pwn import cyclic  # type: ignore
                pattern = cyclic(512)
            except ImportError:
                pattern = b"A" * 512

            # Place pattern in a scratch buffer and emulate
            scratch = load_addr + len(runner._firmware) + 0x1000
            try:
                runner._uc.mem_map(scratch, 0x2000)
            except Exception:
                pass
            result = runner.emulate_overflow_probe(
                func_addr, scratch, pattern, max_insns=20000)

            if result.get("overflow_confirmed"):
                offset = result.get("overflow_offset", -1)
                new_findings.append(Finding(
                    id=_next_id(), stage="emulation",
                    title=f"VxWorks buffer overflow confirmed at {func_addr:#x}"
                          + (f" (offset={offset})" if offset >= 0 else ""),
                    cwe="CWE-120", severity="CRITICAL",
                    component=f"binary:{func_addr:#x}",
                    evidence=str(result),
                    confirmation="CONFIRMED",
                    address=hex(func_addr),
                    analysis_pipeline="vxworks",
                    exploit_score=10.0,
                    emulation_trace=str(result),
                    manual_steps=[
                        f"Overflow confirmed at offset={offset}",
                        "VxWorks: no canary/NX/ASLR — direct shellcode at overwrite address",
                        f"Generate PoC: vxworks/vx_poc_generator.generate_stack_overflow_poc("
                        f"{func_addr:#x}, {offset}, {load_addr:#x}, '{arch}')",
                    ],
                ))
            else:
                _status("-", f"  {func_addr:#x}: {result.get('status', 'no crash')}")

    except ImportError:
        _status("~", "[TOOL_MISSING] unicorn not installed: pip install unicorn")
    except Exception as exc:
        _status("~", f"Unicorn error: {exc}")

    # VX3c — WDB live probe
    if target_ip:
        _status("*", f"VX3c: WDB probe at {target_ip}:17185...")
        try:
            from vxworks.wdb_client import probe_wdb
            wdb = probe_wdb(target_ip)
            if wdb.get("status") == "open":
                new_findings.append(Finding(
                    id=_next_id(), stage="dynamic",
                    title=f"WDB OPEN on {target_ip}:17185 — unauthenticated memory R/W CONFIRMED",
                    cwe="CWE-288", severity="CRITICAL",
                    component=f"network:{target_ip}:17185",
                    evidence=json.dumps(wdb, indent=2)[:500],
                    confirmation="CONFIRMED",
                    analysis_pipeline="vxworks",
                    exploit_score=10.0,
                    disposition="RESOLVED",
                    manual_steps=[
                        f"python3 -c \"from vxworks.wdb_client import wdb_memory_dump; "
                        f"print(wdb_memory_dump('{target_ip}', 0x1000, 256))\"",
                        "Use WDB mem_write to overwrite any function pointer for RCE",
                    ],
                ))
            else:
                _status("-", f"WDB: {wdb.get('status', 'closed')}")
        except Exception as exc:
            _status("~", f"WDB probe error: {exc}")

    # VX3d — VxWorks shell probe
    if target_ip:
        _status("*", f"VX3d: VxWorks shell probe at {target_ip}:5001...")
        try:
            from vxworks.shell_client import probe_vx_shell
            shell = probe_vx_shell(target_ip)
            if shell.get("status") == "open":
                new_findings.append(Finding(
                    id=_next_id(), stage="dynamic",
                    title=f"VxWorks shell OPEN on {target_ip}:5001 — unauthenticated RCE",
                    cwe="CWE-78", severity="CRITICAL",
                    component=f"network:{target_ip}:5001",
                    evidence=json.dumps({
                        "version": shell.get("version_output", "")[:200],
                        "tasks": shell.get("task_list", "")[:200],
                    }),
                    confirmation="CONFIRMED",
                    analysis_pipeline="vxworks",
                    exploit_score=10.0,
                    disposition="RESOLVED",
                    manual_steps=[
                        f"telnet {target_ip} 5001",
                        "Run: i  (task list), version  (OS version)",
                        "RCE: sp(func_addr)  — spawns task at any address",
                    ],
                ))
        except Exception as exc:
            _status("~", f"Shell probe error: {exc}")

    # VX3e — fuzzing
    if target_ip:
        _status("*", f"VX3e: VxWorks service fuzzing at {target_ip}...")
        fuzz_out = os.path.join(out_dir, "fuzz_results")
        try:
            from vxworks.vx_fuzz_runner import fuzz_http_vxworks
            r = fuzz_http_vxworks(target_ip, 80, fuzz_out, max_cases=500)
            _status("+", f"Fuzz HTTP: {r.get('status')} ({r.get('test_cases', 0)} cases)")
        except Exception as exc:
            _status("~", f"Fuzz error: {exc}")

    _status("+", f"VX3 complete: {len(new_findings)} finding(s)")
    return new_findings


def stage_vx4_exploitation(triage: TriageResult, findings: List[Finding],
                            out_dir: str, args) -> List[Finding]:
    """
    VX4 — VxWorks Exploit Chaining
    Generates PoC scripts for confirmed VxWorks findings.
    No ROP needed (no NX).  No info-leak needed (no ASLR).
    """
    _section("STAGE VX4", "VxWorks Exploit Chaining & PoC Generation")
    info     = triage.binary_info
    arch     = triage.arch.lower()
    load_addr = triage.load_address
    target_ip = getattr(args, "target_ip", None)

    poc_dir = os.path.join(out_dir, "poc")
    os.makedirs(poc_dir, exist_ok=True)

    updated = []
    for f in findings:
        if f.analysis_pipeline != "vxworks":
            updated.append(f)
            continue

        if f.exploit_score < 7.0 or f.poc_script:
            updated.append(f)
            continue

        try:
            from vxworks import vx_poc_generator as pocgen
            script = ""

            if "overflow" in f.title.lower() and f.address:
                offset = 0
                m = re.search(r"offset=(\d+)", f.title)
                if m:
                    offset = int(m.group(1))
                elif m := re.search(r"offset=(\d+)", f.emulation_trace):
                    offset = int(m.group(1))
                script = pocgen.generate_stack_overflow_poc(
                    int(f.address, 16) if f.address else 0,
                    offset, load_addr, arch,
                    host=target_ip,
                )
            elif "WDB" in f.title and target_ip:
                script = pocgen.generate_wdb_memwrite_poc(
                    0x10000,   # placeholder func ptr addr
                    load_addr + 0x100,
                    arch, target_ip,
                )
            elif "shell" in f.title.lower() and target_ip:
                script = pocgen.generate_shell_spawn_poc(
                    load_addr + 0x100, target_ip)
            elif "URGENT/11" in f.title:
                script = pocgen.generate_urgent11_poc(
                    target_ip or "TARGET_IP", 80, arch)

            if script:
                poc_path = os.path.join(poc_dir, f"{f.id}_vx_poc.py")
                with open(poc_path, "w") as fh:
                    fh.write(script)
                f.poc_script = script
                f.disposition = "RESOLVED"
                _status("+", f"PoC: {poc_path}")

        except Exception as exc:
            _status("~", f"PoC gen error for {f.id}: {exc}")

        updated.append(f)

    _status("+", f"VX4 complete: {sum(1 for f in updated if f.poc_script)} PoC(s) generated")
    return updated


def run_vxworks_pipeline(path: str, triage: TriageResult,
                         args) -> List[Finding]:
    """
    Top-level VxWorks pipeline dispatcher.
    Calls VX1 → VX2 → VX3 → VX4 → returns findings for shared VX5/VX6.
    """
    _section("VXWORKS PIPELINE", f"Starting VxWorks analysis: {path}")

    # VX1
    vx1_findings, symbols, load_addr = stage_vx1_static(triage, args)
    findings = list(vx1_findings)

    # VX2
    vx2_findings = stage_vx2_ghidra(triage, symbols, load_addr, findings, args)
    findings.extend(vx2_findings)

    # VX3
    vx3_findings = stage_vx3_dynamic(triage, findings, args)
    findings.extend(vx3_findings)

    # VX4
    out_dir = os.path.abspath(getattr(args, "out_dir", "results"))
    findings = stage_vx4_exploitation(triage, findings, out_dir, args)

    return findings


# ── Gap 16: Tool dependency reference ─────────────────────────────────────────
# All tools used by re_agent.py and their install methods:
#
# apt  : binwalk, radare2, binutils (readelf/objdump), checksec, file, xxd,
#         gdb-multiarch, gdbserver, strace, ltrace, qemu-arm, qemu-mips,
#         qemu-x86_64, searchsploit
# pip  : anthropic, pwntools, ropgadget, unicorn, frida-tools, boofuzz,
#         trufflehog, semgrep, pyelftools, intelhex, pefile, capstone
# src  : radamsa (https://gitlab.com/akihe/radamsa — `make && make install`)
# env  : GHIDRA_HOME must point to Ghidra install dir for Stage 2A
#
# Graceful degradation: every tool guarded by _tool_available() or try/except.
# Missing tools emit [TOOL_MISSING] and skip that sub-stage without crashing.

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exploit-first binary analysis agent (agent.md v2.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            All parameters auto-detected from the binary.
            Override flags are escape hatches for when auto-detection fails.

            Examples:
              python3 re_agent.py firmware.bin
              python3 re_agent.py image.elf --skip-ghidra --no-llm
              python3 re_agent.py router.bin --os-type Linux --out-dir ./results
        """),
    )
    parser.add_argument("file", help="Binary or firmware file to analyze")
    parser.add_argument("--arch", choices=["arm", "mips", "x86", "arm64", "riscv", "xtensa"],
                        help="Force architecture")
    parser.add_argument("--endian", choices=["le", "be"], help="Force endianness")
    parser.add_argument("--os-type",
                        choices=["Linux", "VxWorks", "Unknown"],
                        help="Force OS type (VxWorks triggers VxWorks pipeline; Linux/Unknown use Linux pipeline)")
    parser.add_argument("--controller", metavar="NAME", help="MCU name for DB lookup")
    parser.add_argument("--skip-ghidra", action="store_true", help="Skip Stage 2A")
    parser.add_argument("--skip-emulation", action="store_true", help="Skip Stages 3–4")
    parser.add_argument("--skip-dynamic", action="store_true", help="Alias for --skip-emulation")
    parser.add_argument("--output", choices=["console", "json", "html", "all"],
                        default="all", help="Output format (default: all)")
    parser.add_argument("--out-dir", default="results", metavar="DIR",
                        help="Output directory (default: results/)")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip Claude API narrative synthesis")
    parser.add_argument("--exploit-only", action="store_true",
                        help="Re-run Stages 3–4 using saved findings JSON")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Skip OS Confirmation Checkpoint (for CI/automated runs)")
    parser.add_argument("--skip-qemu-vxworks", action="store_true",
                        help="Skip QEMU system-mode emulation in VxWorks pipeline (VX3a)")
    parser.add_argument("--target-ip", metavar="IP",
                        help="Live target IP for WDB/shell/fuzz probes (VxWorks pipeline)")
    parser.add_argument("--load-addr", metavar="HEX", type=lambda x: int(x, 16),
                        default=0,
                        help="Force VxWorks load address (hex, e.g. 0x10000)")
    args = parser.parse_args()

    # Normalise endian
    if args.endian == "le":
        args.endian = "little"
    elif args.endian == "be":
        args.endian = "big"

    path = args.file
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(BANNER)
    print(f"\n[*] Target  : {os.path.abspath(path)}")
    print(f"[*] Size    : {os.path.getsize(path):,} bytes")
    print(f"[*] Started : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    t0 = time.time()

    # ── Gap 3: --exploit-only — skip Stages 0–2, reload from saved results ──
    if args.exploit_only:
        triage, findings = _load_exploit_only_state(args, path)
        if triage is None:
            sys.exit(1)
        _status("+", f"--exploit-only: loaded {len(findings)} findings from prior run")
        confirmed_os = triage.os_type
    else:
        # ── Stage 0 (shared triage) ───────────────────────────────────────────
        triage = stage0_triage(path, args)

        # ── OS Confirmation Checkpoint ────────────────────────────────────────
        confirmed_os = os_confirmation_checkpoint(triage, args)
        triage.os_type = confirmed_os

        # ── Branch: VxWorks or Linux pipeline ────────────────────────────────
        if confirmed_os == "VxWorks":
            findings = run_vxworks_pipeline(path, triage, args)
        else:

            # ── Stage 1 ──────────────────────────────────────────────────────
            findings: List[Finding] = stage1_static(triage, args)
            for f in findings:
                f.analysis_pipeline = "linux"

            # ── Stage 2A ─────────────────────────────────────────────────────
            ghidra_findings = stage2a_ghidra(triage, findings, args)
            for f in ghidra_findings:
                f.analysis_pipeline = "linux"
            findings.extend(ghidra_findings)

            # ── Stage 2B ─────────────────────────────────────────────────────
            fs_findings = stage2b_filesystem(triage, args)
            for f in fs_findings:
                f.analysis_pipeline = "linux"
            findings.extend(fs_findings)

    if confirmed_os != "VxWorks":
        # ── Stage 3 ──────────────────────────────────────────────────────────
        dynamic_findings = stage3_dynamic(triage, findings, args)
        findings.extend(dynamic_findings)

        # ── Stage 4 ──────────────────────────────────────────────────────────
        out_dir = os.path.abspath(args.out_dir)
        findings = stage4_exploitation(triage, findings, out_dir, args)
    else:
        out_dir = os.path.abspath(args.out_dir)

    # ── Stage 5 (shared) ─────────────────────────────────────────────────────
    _section("STAGE 5", "Vulnerability List & Runtime Flags")
    import vuln_list as vl
    vuln_result = vl.build_vuln_list(findings, triage, out_dir)

    # ── Stage 6 (shared) ─────────────────────────────────────────────────────
    stage6_report(triage, vuln_result, args, out_dir)

    elapsed = time.time() - t0
    print(f"[✓] Analysis complete in {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()
