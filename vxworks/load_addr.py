"""
VxWorks load address auto-detection.

Tries methods in order; first success wins.
  0. vxhunter VxTarget.find_loading_address() — tries vx5+vx6 × LE/BE
  1. Scan for WRS_KERNEL_TEXT_START=0x<addr> string in binary
  2. WIND_SYM_TBL self-reference (LE + BE)
  3. Vector table entry cluster (LE + BE, scans first 0x1000 bytes)
  4. String anchor via usrRoot (LE + BE)
  5. Fallback: user-supplied --load-addr or architecture default
"""

import re
import struct
import sys
import os
from typing import Optional

# Architecture-default base addresses (VxWorks BSP convention)
_ARCH_DEFAULTS = {
    "ppc":   0x00100000,
    "mips":  0x80010000,
    "arm":   0x00010000,
    "arm64": 0x00010000,
    "x86":   0x00010000,
    "x86_64": 0x00010000,
}


def _try_vxhunter(data: bytes, endian: str = "big") -> Optional[int]:
    """Try vxhunter for VxWorks 5 and 6, both endians."""
    vxhunter_paths = [
        os.environ.get("VXHUNTER_PATH", ""),
        os.path.expanduser("~/vxhunter/firmware_tools"),
        "/opt/vxhunter/firmware_tools",
    ]
    for p in vxhunter_paths:
        if p and os.path.isfile(os.path.join(p, "vxhunter_core_py3.py")):
            if p not in sys.path:
                sys.path.insert(0, p)
            break
    try:
        from vxhunter_core_py3 import VxTarget  # type: ignore
        # Try triage-endian first, then opposite; try both vx_version 5 and 6
        endian_first = endian == "big"
        for vx_ver in (5, 6):
            for is_be in (endian_first, not endian_first):
                t = VxTarget(firmware=data, vx_version=vx_ver, is_big_endian=is_be)
                t.find_loading_address()
                if t.load_address and t.load_address > 0:
                    return t.load_address
    except Exception:
        pass
    return None


def _unpack4(data: bytes, offset: int, big_endian: bool) -> Optional[int]:
    fmt = ">I" if big_endian else "<I"
    try:
        return struct.unpack_from(fmt, data, offset)[0]
    except struct.error:
        return None


def detect_load_address(data: bytes, arch: str = "arm",
                        endian: str = "big",
                        fallback: int = 0) -> tuple[int, str]:
    """
    Return (load_address, method_used).
    method_used is one of: vxhunter, wrs_string, sym_self_ref, vector_table,
                           string_anchor, fallback_arg, arch_default
    """
    is_be = endian == "big"

    # Method 0: vxhunter (vx5+vx6, both endians)
    vx_addr = _try_vxhunter(data, endian)
    if vx_addr:
        return vx_addr, "vxhunter"

    # Method 1: WRS_KERNEL_TEXT_START=0x<addr>
    m = re.search(rb"WRS_KERNEL_TEXT_START\s*=\s*(0x[0-9a-fA-F]+)", data)
    if m:
        try:
            addr = int(m.group(1), 16)
            if addr > 0:
                return addr, "wrs_string"
        except ValueError:
            pass

    # Method 2: WIND_SYM_TBL self-reference — try triage endian then opposite
    vx_offset = data.find(b"VxWorks")
    if vx_offset > 0:
        scan_end = min(len(data) - 4, 0x10000)
        for be in (is_be, not is_be):
            for i in range(0, scan_end, 4):
                word = _unpack4(data, i, be)
                if word is None:
                    break
                if word > 0x10000 and (word & 0xFFF) == (vx_offset & 0xFFF):
                    candidate = word - vx_offset
                    if 0 < candidate < 0xF0000000:
                        return candidate, "sym_self_ref"

    # Method 3: vector table / reset vector cluster
    # Extended scan to 0x1000 to cover images with a BSP header before the table.
    # Try triage endian first, then opposite.
    if len(data) >= 64:
        scan_end = min(len(data) - 32, 0x1000)
        for be in (is_be, not is_be):
            for base in range(0, scan_end, 4):
                vals = []
                for i in range(8):
                    v = _unpack4(data, base + i * 4, be)
                    if v is None:
                        break
                    vals.append(v)
                candidates = [v for v in vals
                              if 0x00010000 <= v <= 0xEFFFFFFF and v & 3 == 0]
                if len(candidates) >= 4:
                    candidates.sort()
                    addr = candidates[len(candidates) // 2] & 0xFFFF0000
                    return addr, "vector_table"

    # Method 4: string anchor via usrRoot — try triage endian first, then opposite
    usr_root = data.find(b"usrRoot")
    if usr_root > 0:
        scan_end = min(len(data) - 4, 0x4000)
        for be in (is_be, not is_be):
            for i in range(0, scan_end, 4):
                word = _unpack4(data, i, be)
                if word is None:
                    break
                if word > 0x10000:
                    candidate = word - usr_root
                    if 0 < candidate < 0xF0000000 and candidate % 0x1000 == 0:
                        return candidate, "string_anchor"

    # Method 5: user-supplied fallback
    if fallback > 0:
        return fallback, "fallback_arg"

    default = _ARCH_DEFAULTS.get(arch, 0x00010000)
    return default, "arch_default"
