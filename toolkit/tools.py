"""
Wrappers around external tools: binwalk, strings, radare2, readelf, file.
"""
import re
import subprocess
import tempfile
import os
from typing import Optional
from .detector import BinaryInfo
from .mcu import MCUInfo


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], input_data: bytes | None = None, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            timeout=timeout,
        )
        return (result.stdout + result.stderr).decode(errors="replace")
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return f"[tool not found: {cmd[0]}]"
    except Exception as exc:
        return f"[error: {exc}]"


def _write_temp(data: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return path


# ── file ──────────────────────────────────────────────────────────────────────

def run_file(info: BinaryInfo) -> str:
    return _run(["file", info.path]).strip()


# ── strings ───────────────────────────────────────────────────────────────────

_BORING = re.compile(
    r"^[\x20-\x7e]{1,3}$|^[0-9a-fA-F]+$|^\s+$"
)

_INTERESTING_PATTERNS = re.compile(
    r"(?i)(password|passw|secret|key|token|api|flag|admin|root|sudo|"
    r"http|ftp|ssh|telnet|uart|debug|boot|flash|erase|unlock|firmware|"
    r"version|copyright|error|fail|assert|panic|fault|crash|stack|heap|"
    r"malloc|free|printf|scanf|gets|strcpy|sprintf|cmd|shell|exec|system|"
    r"auth|login|user|pass|cert|sha|md5|aes|rsa|crc|nvs|nvram|eeprom|"
    r"config|gpio|i2c|spi|uart|can|usb|ethernet|wifi|ble|ota|dfu|jtag|swd|"
    r"vTask|xQueue|xSemaphore|osThread|chThd|tx_thread|k_thread|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


def run_strings(info: BinaryInfo, min_len: int = 5) -> dict:
    tmp = _write_temp(info.raw_bytes)
    try:
        out = _run(["strings", "-n", str(min_len), tmp])
    finally:
        os.unlink(tmp)

    all_strings = [s for s in out.splitlines() if s and not _BORING.match(s)]
    interesting = [s for s in all_strings if _INTERESTING_PATTERNS.search(s)]

    return {
        "total": len(all_strings),
        "interesting": interesting[:200],
        "all_sample": all_strings[:50],
    }


# ── binwalk ───────────────────────────────────────────────────────────────────

def run_binwalk(info: BinaryInfo) -> dict:
    tmp = _write_temp(info.raw_bytes)
    try:
        signatures = _run(["binwalk", tmp])
        entropy    = _run(["binwalk", "--entropy", tmp])
    finally:
        os.unlink(tmp)

    return {
        "signatures": signatures.strip(),
        "entropy":    entropy.strip(),
    }


# ── radare2 ───────────────────────────────────────────────────────────────────

def run_radare2(
    info: BinaryInfo,
    mcu: MCUInfo | None = None,
    max_functions: int = 30,
) -> dict:
    """
    Disassemble with radare2.
    Architecture priority: MCUInfo (user-specified) > ELF header > raw binary default.
    """
    # Resolve architecture settings
    if mcu:
        r2_arch = mcu.r2_arch
        r2_bits = mcu.r2_bits
        r2_cpu  = mcu.r2_cpu
        load_addr = info.load_address if info.load_address is not None else mcu.flash_base
    elif info.format == "elf":
        # ELF — let r2 parse natively, just need arch for display
        r2_arch = _elf_arch(info.architecture)
        r2_bits = _elf_bits(info.architecture)
        r2_cpu  = None
        load_addr = info.load_address or 0
    else:
        # Raw fallback — generic ARM Cortex-M
        r2_arch = "arm"
        r2_bits = "16"
        r2_cpu  = "cortex-m4"
        load_addr = info.load_address or 0x08000000

    if info.format == "elf":
        tmp = _write_temp(info.raw_bytes, suffix=".elf")
        r2_cmd = [
            "r2", "-q", "-e", "scr.color=0",
            "-A", "-c", "afl;pdf @main 2>/dev/null;iz;",
            tmp,
        ]
    else:
        tmp = _write_temp(info.raw_bytes)
        r2_cmd = ["r2", "-q", "-e", "scr.color=0",
                  "-a", r2_arch, "-b", r2_bits,
                  "-m", hex(load_addr)]
        if r2_cpu:
            r2_cmd += ["-e", f"asm.cpu={r2_cpu}"]
        r2_cmd += ["-A", "-c", "afl;iz;", tmp]

    try:
        out = _run(r2_cmd, timeout=90)
    finally:
        os.unlink(tmp)

    functions = _extract_afl(out)
    strings_r2 = [l.strip() for l in out.splitlines() if l.startswith("vaddr=")]

    return {
        "arch":      r2_arch,
        "bits":      r2_bits,
        "cpu":       r2_cpu,
        "load_addr": hex(load_addr),
        "functions": functions[:max_functions],
        "strings":   strings_r2[:50],
        "raw":       out[:6000],
    }


def _extract_afl(out: str) -> list[str]:
    lines = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("0x") and len(s) > 10:
            lines.append(s)
    return lines[:50]


def _elf_arch(arch: str | None) -> str:
    mapping = {
        "x86": "x86", "x86_64": "x86", "arm": "arm",
        "aarch64": "arm", "mips": "mips", "riscv": "riscv",
        "powerpc": "ppc", "xtensa": "xtensa", "avr": "avr",
    }
    return mapping.get(arch or "arm", "arm")


def _elf_bits(arch: str | None) -> str:
    if arch in ("x86_64", "aarch64"):
        return "64"
    return "32"


# ── readelf ───────────────────────────────────────────────────────────────────

def run_readelf(info: BinaryInfo) -> Optional[dict]:
    if info.format != "elf":
        return None

    headers  = _run(["readelf", "-h",  info.path])
    sections = _run(["readelf", "-S",  info.path])
    symbols  = _run(["readelf", "-s",  info.path])
    dynamic  = _run(["readelf", "-d",  info.path])

    return {
        "headers":  headers.strip(),
        "sections": sections.strip(),
        "symbols":  symbols.strip()[:4000],
        "dynamic":  dynamic.strip(),
    }
