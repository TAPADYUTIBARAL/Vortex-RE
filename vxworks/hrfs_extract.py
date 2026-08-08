"""
VxWorks HRFS (Host-Readable File System) and dosFs extractor.

VxWorks HRFS is a proprietary FAT-like filesystem.  This module:
  1. Detects HRFS / dosFs signatures in raw binary
  2. Attempts extraction via:
     a. vxhunter fs subcommand (if available)
     b. dosfstools / mtools for FAT-compatible dosFs
     c. Raw sector dump for HRFS with manual header parse

Additional filesystems present in VxWorks firmware:
  - TrueFFS (NAND management layer over JFFS2/dosFs)
  - RomFs (read-only, same as Linux romfs)
"""

import os
import re
import shutil
import struct
import subprocess
import tempfile


_HRFS_MAGIC    = b"HRFS"
_DOSFS_MAGIC   = b"\xEB\x3C\x90"     # x86 boot sector jump (common dosFs)
_DOSFS_SIG     = b"\x55\xAA"         # offset 510 boot signature


def _run(cmd: list, timeout: int = 60) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).decode(errors="replace")
    except Exception as exc:
        return False, str(exc)


def detect_vxworks_filesystems(data: bytes) -> list[dict]:
    """Return list of {fs_type, offset, size_hint} for VxWorks-specific FSes."""
    found = []

    # HRFS signature
    offset = 0
    while True:
        idx = data.find(_HRFS_MAGIC, offset)
        if idx == -1:
            break
        found.append({"fs_type": "hrfs", "offset": idx,
                      "description": "VxWorks HRFS"})
        offset = idx + 1

    # dosFs: look for boot signature at byte 510 of each 512-byte-aligned sector
    for off in range(0, len(data) - 512, 512):
        if data[off + 510:off + 512] == _DOSFS_SIG:
            found.append({"fs_type": "dosfs", "offset": off,
                          "description": "dosFs / FAT boot sector"})

    found.sort(key=lambda x: x["offset"])
    return found


def extract_hrfs(data: bytes, offset: int, outdir: str) -> dict:
    """Attempt HRFS extraction.  vxhunter preferred; raw dump fallback."""
    os.makedirs(outdir, exist_ok=True)
    tmp = tempfile.mktemp(suffix=".hrfs")
    try:
        with open(tmp, "wb") as f:
            f.write(data[offset:])

        if shutil.which("vxhunter"):
            ok, out = _run(["vxhunter", "fs", "-f", tmp, "-o", outdir], timeout=120)
            if ok:
                return {"status": "ok", "tool": "vxhunter", "output_dir": outdir}

        # Raw dump: parse HRFS header
        # HRFS header: magic[4] version[4] block_size[4] total_blocks[4]
        if len(data) - offset < 16:
            return {"status": "failed", "reason": "too small"}
        hdr = data[offset:offset + 16]
        magic, ver, blk_sz, total = struct.unpack(">4sIII", hdr)
        if magic != _HRFS_MAGIC:
            return {"status": "failed", "reason": "bad magic"}
        fs_size = blk_sz * total
        raw_out = os.path.join(outdir, "hrfs_raw.bin")
        with open(raw_out, "wb") as f:
            f.write(data[offset:offset + fs_size])
        return {"status": "raw_dump", "output_file": raw_out,
                "block_size": blk_sz, "total_blocks": total,
                "note": "install vxhunter for full extraction"}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def extract_dosfs(data: bytes, offset: int, outdir: str) -> dict:
    """Extract dosFs using mtools."""
    os.makedirs(outdir, exist_ok=True)
    tmp = tempfile.mktemp(suffix=".img")
    try:
        with open(tmp, "wb") as f:
            f.write(data[offset:])

        if shutil.which("mcopy"):
            ok, out = _run(["mcopy", "-i", tmp, "-s", "::/", outdir])
            if ok:
                return {"status": "ok", "tool": "mcopy", "output_dir": outdir}

        # Fallback: mdir to list, then manual extraction attempt
        if shutil.which("mdir"):
            ok, out = _run(["mdir", "-i", tmp])
            return {"status": "listing_only", "listing": out[:1000],
                    "note": "install mtools for full extraction"}

        return {"status": "tool_missing", "tool": "mtools",
                "install": "apt install mtools"}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def extract_vxworks_filesystems(firmware_path: str, outdir: str) -> dict:
    """Top-level: scan firmware and extract all VxWorks-specific filesystems."""
    with open(firmware_path, "rb") as f:
        data = f.read()

    found = detect_vxworks_filesystems(data)
    results = []
    for fs in found:
        sub = os.path.join(outdir, f"{fs['fs_type']}_{fs['offset']:#010x}")
        if fs["fs_type"] == "hrfs":
            r = extract_hrfs(data, fs["offset"], sub)
        elif fs["fs_type"] == "dosfs":
            r = extract_dosfs(data, fs["offset"], sub)
        else:
            r = {"status": "unsupported"}
        results.append({**fs, "offset": hex(fs["offset"]), "extraction": r})

    return {
        "filesystems_found": len(found),
        "results": results,
        "output_dir": outdir,
    }
