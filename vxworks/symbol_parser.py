"""
VxWorks WIND_SYM_TBL parser.

Supports 3 on-disk formats:
  5.x  — 12 bytes: [namePtr:4][value:4][type:2][group:2]
  6.x  — 12 bytes: [namePtr:4][value:4][type:1][reserved:1][group:2]
  7.x  — 16 bytes: [namePtr:4][value:4][type:4][group:4]

Strategy:
  1. Import VxTarget from PAGalaxyLab/vxhunter (cloned repo, NOT pip install)
     Default search path: ~/vxhunter/firmware_tools/
     Override with env var: VXHUNTER_PATH=/path/to/vxhunter/firmware_tools
  2. Fallback: heuristic scan for the symbol table in raw bytes
  3. Produce JSON output for downstream Ghidra scripts
"""

import json
import os
import re
import struct
import sys
from typing import Optional


_SYM_TYPES = {
    0x0: "undefined", 0x1: "local", 0x2: "global",
    0x3: "abs_local", 0x4: "abs_global",
    0x5: "bss_local", 0x6: "bss_global",
    0x7: "text_local", 0x8: "text_global",
    0x9: "data_local", 0xa: "data_global",
    0xb: "comm_local", 0xc: "comm_global",
}

# ── vxhunter library loader ───────────────────────────────────────────────────

def _vxhunter_path() -> Optional[str]:
    """Return path to vxhunter_core_py3.py directory, or None."""
    candidates = [
        os.environ.get("VXHUNTER_PATH", ""),
        os.path.expanduser("~/vxhunter/firmware_tools"),
        "/opt/vxhunter/firmware_tools",
    ]
    for p in candidates:
        if p and os.path.isfile(os.path.join(p, "vxhunter_core_py3.py")):
            return p
    return None


def _load_vxtarget():
    """Import VxTarget from the cloned vxhunter repo. Returns class or None."""
    path = _vxhunter_path()
    if not path:
        return None
    if path not in sys.path:
        sys.path.insert(0, path)
    try:
        from vxhunter_core_py3 import VxTarget  # type: ignore
        return VxTarget
    except ImportError:
        return None


def parse_symbols_vxhunter(firmware_path: str, load_addr: int,
                            out_json: str) -> dict:
    """Use vxhunter VxTarget library to extract symbol table."""
    VxTarget = _load_vxtarget()
    if VxTarget is None:
        return {
            "status": "tool_missing",
            "tool": "vxhunter",
            "install": (
                "git clone https://github.com/PAGalaxyLab/vxhunter ~/vxhunter\n"
                "# No pip install needed — used directly as a library"
            ),
        }

    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    # Detect version + endianness to configure VxTarget
    version   = 5 if b"VxWorks 5" in firmware_data else 6
    big_endian = _guess_big_endian(firmware_data)

    try:
        target = VxTarget(firmware=firmware_data,
                          vx_version=version,
                          is_big_endian=big_endian)
        target.find_symbol_table()

        # If caller already found load address, set it; otherwise let vxhunter find it
        if load_addr:
            target.load_address = load_addr
        else:
            target.find_loading_address()

        raw_symbols = target.get_symbols() or []
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    # Normalise to our schema: {name, address, type, name_ptr}
    symbols = []
    for s in raw_symbols:
        name = s.get("symbol_name", b"")
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        symbols.append({
            "name":     name,
            "address":  hex(s.get("symbol_dest_addr", 0)),
            "type":     hex(s.get("symbol_flag", 0)),
            "name_ptr": hex(s.get("symbol_name_addr", 0)),
        })

    result = {
        "status": "ok",
        "source": "vxhunter",
        "load_address": hex(target.load_address or load_addr),
        "symbol_count": len(symbols),
        "symbols": symbols,
    }
    with open(out_json, "w") as f:
        json.dump(result, f, indent=2)

    return result


def _guess_big_endian(data: bytes) -> bool:
    """Heuristic: VxWorks PPC/MIPS are big-endian; ARM/x86 little-endian."""
    if b"PowerPC" in data or b"MIPS" in data or b"Wind River" in data[:256]:
        return True
    return False


def _find_string_table(data: bytes, load_addr: int) -> dict[int, str]:
    """Build addr→name map by scanning for null-terminated ASCII strings."""
    strings: dict[int, str] = {}
    i = 0
    while i < len(data):
        end = data.find(b"\x00", i)
        if end == -1:
            break
        chunk = data[i:end]
        if 4 <= len(chunk) <= 128:
            try:
                s = chunk.decode("ascii")
                if re.match(r"^[A-Za-z_][A-Za-z0-9_:@\.]*$", s):
                    strings[load_addr + i] = s
            except UnicodeDecodeError:
                pass
        i = end + 1
    return strings


def _heuristic_parse(data: bytes, load_addr: int,
                     version: str = "auto") -> list[dict]:
    """
    Heuristic scan for WIND_SYM_TBL entries.

    Each entry: [namePtr:4][value:4][type:2|1|4][...] — total 12 or 16 bytes.
    We look for clusters where namePtr and value both resolve to plausible
    addresses within the binary.
    """
    strings = _find_string_table(data, load_addr)
    symbols: list[dict] = []
    size = len(data)

    # Try entry sizes 12 and 16
    for entry_size in (12, 16):
        count = 0
        for offset in range(0, size - entry_size, entry_size):
            if version == "7.x" and entry_size != 16:
                continue
            if version in ("5.x", "6.x") and entry_size != 12:
                continue

            raw = data[offset:offset + entry_size]
            try:
                name_ptr = struct.unpack_from(">I", raw, 0)[0]
                value    = struct.unpack_from(">I", raw, 4)[0]
                sym_type = struct.unpack_from(">H", raw, 8)[0] & 0xFF
            except struct.error:
                continue

            # namePtr must point into the binary's string area
            name_file_off = name_ptr - load_addr
            if not (0 <= name_file_off < size):
                continue

            name = strings.get(name_ptr, "")
            if not name:
                continue

            value_file_off = value - load_addr
            if not (0 <= value_file_off < size):
                continue

            symbols.append({
                "name":       name,
                "address":    hex(value),
                "type":       _SYM_TYPES.get(sym_type, f"0x{sym_type:x}"),
                "name_ptr":   hex(name_ptr),
                "file_offset": hex(offset),
            })
            count += 1

        if count > 50:  # enough to call it a win
            break

    return symbols


def parse_symbols_heuristic(firmware_path: str, load_addr: int,
                             out_json: str, version: str = "auto") -> dict:
    """Heuristic fallback when vxhunter is not available."""
    with open(firmware_path, "rb") as f:
        data = f.read()

    symbols = _heuristic_parse(data, load_addr, version)

    result = {
        "status": "ok" if symbols else "no_symbols",
        "source": "heuristic",
        "load_address": hex(load_addr),
        "symbol_count": len(symbols),
        "symbols": symbols,
    }

    with open(out_json, "w") as f:
        json.dump(result, f, indent=2)

    return result


def detect_vxworks_version(data: bytes) -> str:
    """Return '5.x', '6.x', '7.x', or 'unknown' from binary string markers."""
    if b"VxWorks 7" in data or b"VxWorks7" in data:
        return "7.x"
    if b"VxWorks 6" in data or b"VxWorks6" in data:
        return "6.x"
    if b"VxWorks 5" in data or b"VxWorks5" in data:
        return "5.x"
    # Version string like "VxWorks (for <board>) version 5.5.1"
    m = re.search(rb"version\s+(\d)\.(\d)", data)
    if m:
        major = int(m.group(1))
        if major == 5:
            return "5.x"
        if major == 6:
            return "6.x"
        if major >= 7:
            return "7.x"
    return "unknown"


def extract_symbols(firmware_path: str, load_addr: int,
                    out_json: str) -> dict:
    """
    Top-level entry point.  Tries vxhunter first, heuristic fallback.
    Returns result dict with 'status', 'symbol_count', 'source', 'data'.
    """
    # Try vxhunter
    result = parse_symbols_vxhunter(firmware_path, load_addr, out_json)
    if result["status"] == "ok":
        return result

    # Fallback
    with open(firmware_path, "rb") as f:
        data = f.read()
    version = detect_vxworks_version(data)
    result = parse_symbols_heuristic(firmware_path, load_addr, out_json, version)
    return result
