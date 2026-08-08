"""
Firmware extraction: detect and extract embedded filesystems.

Discovery order:
  1. Scan with binwalk to find all signatures + offsets
  2. For each identified filesystem → run the dedicated extraction tool
  3. Fall back to binwalk -e for anything not handled by a dedicated tool
"""
import os
import re
import shutil
import struct
import subprocess
import tempfile


# ── filesystem magic signatures ───────────────────────────────────────────────

# (label, magic_bytes, search_offset, description)
# search_offset=None means scan anywhere in the file
_FS_MAGIC: list[tuple[str, bytes, int | None, str]] = [
    ("squashfs",  b"sqsh",           None, "SquashFS (LE)"),
    ("squashfs",  b"hsqs",           None, "SquashFS (BE)"),
    ("squashfs",  b"sqsquash",       None, "SquashFS v4"),
    ("jffs2",     b"\x85\x19",       None, "JFFS2 (LE)"),
    ("jffs2",     b"\x19\x85",       None, "JFFS2 (BE)"),
    ("ubifs",     b"\x31\x18\x00\x00", None, "UBIFS superblock"),
    ("ubi",       b"UBI#",           None, "UBI image"),
    ("yaffs2",    b"\x03\x00\x00\x00\xff\xff", None, "YAFFS2 chunk tag"),
    ("yaffs",     b"YAFFS",          None, "YAFFS marker"),
    ("cramfs",    b"\x45\x3d\xcd\x28", None, "CramFS (LE)"),
    ("cramfs",    b"\x28\xcd\x3d\x45", None, "CramFS (BE)"),
    ("littlefs",  b"littlefs",       None, "littlefs marker"),
    ("littlefs",  b"\x4c\x4c\x46\x54", None, "littlefs superblock"),
    ("f2fs",      b"\x10\x20\xf5\xf2", 1024, "F2FS superblock"),
    ("ext4",      b"\x53\xef",       1080, "ext2/3/4 superblock"),
    ("romfs",     b"-rom1fs-",       0,    "ROMFS"),
    ("cpio",      b"070701",         None, "CPIO (newc)"),
    ("cpio",      b"070702",         None, "CPIO (CRC newc)"),
    ("tar",       b"ustar",          257,  "TAR archive"),
    ("gzip",      b"\x1f\x8b",       None, "gzip compressed"),
    ("zlib",      b"\x78\x9c",       None, "zlib compressed"),
    ("lzma",      b"\x5d\x00\x00",   None, "LZMA compressed"),
    ("xz",        b"\xfd\x37\x7a\x58\x5a\x00", None, "XZ compressed"),
    ("bz2",       b"BZh",            None, "bzip2 compressed"),
    ("lz4",       b"\x04\x22\x4d\x18", None, "LZ4 frame"),
    ("zstd",      b"\x28\xb5\x2f\xfd", None, "Zstandard"),
    ("fat",       b"\x55\xaa",       510,  "FAT/MBR boot sector"),
]


def scan_for_filesystems(data: bytes) -> list[dict]:
    """Return list of {fs_type, offset, description} for all found signatures."""
    found = []
    seen_offsets = set()

    for fs_type, magic, fixed_offset, desc in _FS_MAGIC:
        if fixed_offset is not None:
            # Check at specific offset only
            end = fixed_offset + len(magic)
            if end <= len(data) and data[fixed_offset:end] == magic:
                key = (fs_type, fixed_offset)
                if key not in seen_offsets:
                    seen_offsets.add(key)
                    found.append({"fs_type": fs_type, "offset": fixed_offset, "description": desc})
        else:
            # Scan entire file
            offset = 0
            while True:
                idx = data.find(magic, offset)
                if idx == -1:
                    break
                key = (fs_type, idx)
                if key not in seen_offsets:
                    seen_offsets.add(key)
                    found.append({"fs_type": fs_type, "offset": idx, "description": desc})
                offset = idx + 1

    found.sort(key=lambda x: x["offset"])
    return found


# ── extraction tools ──────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int = 120) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = (r.stdout + r.stderr).decode(errors="replace")
        return r.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, f"[timeout after {timeout}s]"
    except Exception as exc:
        return False, f"[error: {exc}]"


def _write_slice(data: bytes, offset: int, path: str) -> None:
    with open(path, "wb") as f:
        f.write(data[offset:])


# ── per-filesystem extractors ─────────────────────────────────────────────────

def _extract_squashfs(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".sqfs")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"squashfs_{offset:#010x}")
    try:
        if not _tool_available("unsquashfs"):
            return {"status": "tool_missing", "tool": "unsquashfs",
                    "install": "apt install squashfs-tools"}
        ok, out = _run(["unsquashfs", "-d", dst, tmp])
        return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_jffs2(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".jffs2")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"jffs2_{offset:#010x}")
    try:
        if not _tool_available("jefferson"):
            return {"status": "tool_missing", "tool": "jefferson",
                    "install": "pip install jefferson"}
        ok, out = _run(["jefferson", "-d", dst, tmp])
        return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_ubifs(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".ubifs")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"ubifs_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        tool = "ubireader_extract_files"
        if not _tool_available(tool):
            return {"status": "tool_missing", "tool": tool,
                    "install": "pip install ubi_reader"}
        ok, out = _run([tool, "-o", dst, tmp])
        return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_ubi(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".ubi")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"ubi_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        tool = "ubireader_extract_images"
        if not _tool_available(tool):
            return {"status": "tool_missing", "tool": tool,
                    "install": "pip install ubi_reader"}
        ok, out = _run([tool, "-o", dst, tmp])
        return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_yaffs2(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".yaffs2")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"yaffs2_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        if _tool_available("unyaffs"):
            ok, out = _run(["unyaffs", tmp, dst])
            return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
        if _tool_available("yaffshiv"):
            ok, out = _run(["yaffshiv", "-d", dst, tmp])
            return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
        return {"status": "tool_missing", "tool": "unyaffs or yaffshiv",
                "install": "apt install unyaffs  OR  pip install yaffshiv"}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_cramfs(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".cramfs")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"cramfs_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        if not _tool_available("cramfsck"):
            return {"status": "tool_missing", "tool": "cramfsck",
                    "install": "apt install cramfsprogs"}
        ok, out = _run(["cramfsck", "-x", dst, tmp])
        return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_littlefs(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".lfs")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"littlefs_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        if _tool_available("lfs"):
            ok, out = _run(["lfs", "--read", tmp, dst])
            return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
        # Try Python littlefs package
        try:
            import littlefs  # type: ignore
            with open(tmp, "rb") as f:
                img = f.read()
            fs = littlefs.LittleFS(block_size=4096, block_count=len(img) // 4096)
            fs.context.buffer = bytearray(img)
            _dump_littlefs(fs, "/", dst)
            return {"status": "ok", "output_dir": dst, "tool": "littlefs-python"}
        except ImportError:
            pass
        return {"status": "tool_missing", "tool": "lfs or littlefs-python",
                "install": "pip install littlefs-python  OR  apt install littlefs-tools"}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _dump_littlefs(fs, src_path: str, dst_base: str) -> None:
    try:
        for entry in fs.scandir(src_path):
            dst = os.path.join(dst_base, entry.name)
            if entry.type == 1:   # file
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with fs.open(f"{src_path}/{entry.name}", "rb") as f:
                    data = f.read()
                with open(dst, "wb") as f:
                    f.write(data)
            elif entry.type == 2:  # dir
                os.makedirs(dst, exist_ok=True)
                _dump_littlefs(fs, f"{src_path}/{entry.name}", dst)
    except Exception:
        pass


def _extract_f2fs(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".f2fs")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"f2fs_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        if _tool_available("fsck.f2fs"):
            ok, out = _run(["fsck.f2fs", tmp])
            return {"status": "check_only", "output_dir": dst,
                    "note": "f2fs requires kernel mount for extraction",
                    "log": out[:500]}
        return {"status": "tool_missing", "tool": "fsck.f2fs",
                "install": "apt install f2fs-tools"}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_ext(data: bytes, offset: int, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".ext")
    _write_slice(data, offset, tmp)
    dst = os.path.join(outdir, f"ext_{offset:#010x}")
    os.makedirs(dst, exist_ok=True)
    try:
        if _tool_available("debugfs"):
            ok, out = _run(["debugfs", "-R", f"rdump / {dst}", tmp])
            return {"status": "ok" if ok else "failed", "output_dir": dst, "log": out[:500]}
        if _tool_available("e2cp"):
            return {"status": "partial", "note": "use e2tools for full extraction",
                    "output_dir": dst}
        return {"status": "tool_missing", "tool": "debugfs",
                "install": "apt install e2tools"}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _extract_gzip(data: bytes, offset: int, outdir: str) -> dict:
    import gzip, io
    dst = os.path.join(outdir, f"gzip_{offset:#010x}.bin")
    try:
        decompressed = gzip.decompress(data[offset:])
        with open(dst, "wb") as f:
            f.write(decompressed)
        return {"status": "ok", "output_file": dst, "size": len(decompressed)}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def _extract_binwalk_generic(data: bytes, outdir: str) -> dict:
    tmp = tempfile.mktemp(suffix=".bin")
    extract_dir = os.path.join(outdir, "binwalk_extracted")
    with open(tmp, "wb") as f:
        f.write(data)
    try:
        ok, out = _run(["binwalk", "-e", "--directory", extract_dir, tmp])
        return {
            "status": "ok" if ok else "failed",
            "output_dir": extract_dir,
            "log": out[:1000],
        }
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ── dispatcher ────────────────────────────────────────────────────────────────

_EXTRACTORS = {
    "squashfs": _extract_squashfs,
    "jffs2":    _extract_jffs2,
    "ubifs":    _extract_ubifs,
    "ubi":      _extract_ubi,
    "yaffs2":   _extract_yaffs2,
    "yaffs":    _extract_yaffs2,
    "cramfs":   _extract_cramfs,
    "littlefs": _extract_littlefs,
    "f2fs":     _extract_f2fs,
    "ext4":     _extract_ext,
    "gzip":     _extract_gzip,
}


def extract_all(data: bytes, outdir: str) -> dict:
    """
    Full extraction pass:
      1. Scan for filesystem signatures
      2. Run dedicated tool for each found FS
      3. Binwalk generic extraction as final pass

    Returns summary dict with found filesystems and extraction results.
    """
    os.makedirs(outdir, exist_ok=True)

    found = scan_for_filesystems(data)
    results = []
    handled_types = set()

    for sig in found:
        fs_type = sig["fs_type"]
        offset  = sig["offset"]

        # Only extract each FS type once (first occurrence)
        if fs_type in handled_types:
            continue
        handled_types.add(fs_type)

        extractor = _EXTRACTORS.get(fs_type)
        if extractor:
            try:
                r = extractor(data, offset, outdir)
            except Exception as exc:
                r = {"status": "error", "error": str(exc)}
            results.append({
                "fs_type":     fs_type,
                "offset":      hex(offset),
                "description": sig["description"],
                "extraction":  r,
            })
        else:
            results.append({
                "fs_type":     fs_type,
                "offset":      hex(offset),
                "description": sig["description"],
                "extraction":  {"status": "no_dedicated_tool"},
            })

    # Always run binwalk generic extraction as a safety net
    bw_result = _extract_binwalk_generic(data, outdir)

    return {
        "filesystems_found": len(found),
        "signatures":        found,
        "dedicated_results": results,
        "binwalk_extract":   bw_result,
        "output_dir":        outdir,
    }


# ── Cortex-M vector table parser ─────────────────────────────────────────────

_CORTEXM_VECTORS = [
    "Initial_SP",
    "Reset_Handler",
    "NMI_Handler",
    "HardFault_Handler",
    "MemManage_Handler",
    "BusFault_Handler",
    "UsageFault_Handler",
    "Reserved_0x1C",
    "Reserved_0x20",
    "Reserved_0x24",
    "Reserved_0x28",
    "SVC_Handler",
    "DebugMon_Handler",
    "Reserved_0x34",
    "PendSV_Handler",
    "SysTick_Handler",
]


def parse_cortexm_vectors(data: bytes, flash_base: int = 0x08000000) -> dict:
    """Parse Cortex-M interrupt vector table at the start of flash."""
    if len(data) < 8:
        return {"error": "too small"}

    num = min(48, len(data) // 4)
    vectors = []
    for i in range(num):
        val = struct.unpack_from("<I", data, i * 4)[0]
        name = _CORTEXM_VECTORS[i] if i < len(_CORTEXM_VECTORS) else f"IRQ_{i - 16}"
        addr = val & ~1          # clear Thumb bit for display
        is_thumb = bool(val & 1) # all handlers should be Thumb
        vectors.append({
            "index":   i,
            "name":    name,
            "raw":     hex(val),
            "address": hex(addr),
            "thumb":   is_thumb,
        })

    sp  = vectors[0]["raw"] if vectors else "?"
    rst = vectors[1]["address"] if len(vectors) > 1 else "?"

    return {
        "initial_sp":    sp,
        "reset_handler": rst,
        "vectors":       vectors,
        "flash_base":    hex(flash_base),
    }


# ── RTOS fingerprinting ───────────────────────────────────────────────────────

_RTOS_SIGNATURES: dict[str, list[bytes]] = {
    "FreeRTOS":  [b"FreeRTOS", b"vTaskDelay", b"xQueueCreate", b"pvPortMalloc",
                  b"Tmr Svc", b"IDLE", b"xTaskCreate"],
    "Zephyr":    [b"zephyr", b"k_thread_create", b"z_thread_entry", b"CONFIG_SOC"],
    "ThreadX":   [b"ThreadX", b"_tx_thread_", b"tx_thread_create", b"Azure RTOS"],
    "VxWorks":   [b"VxWorks", b"Wind River", b"vxworks", b"taskSpawn",
                  b"wdbTgtSvr", b"usrRoot", b"WIND version", b"WRS_KERNEL_TEXT_START",
                  b"ipnet", b"IPNET", b"vxTaskLib", b"sysClkRateGet"],
    "QNX":       [b"Neutrino", b"procnto", b"io-pkt", b"slogger",
                  b"QNX", b"qnx_spawn", b"QSSL", b"photon"],
    "RIOT OS":   [b"RIOT", b"riot_board", b"kernel_pid_t", b"thread_create"],
    "mbed OS":   [b"mbed", b"MBED_", b"rtos::Thread", b"osThreadCreate"],
    "ChibiOS":   [b"ChibiOS", b"chThdCreate", b"chSysInit", b"CH_KERNEL"],
    "NuttX":     [b"NuttX", b"nuttx", b"nx_start", b"CONFIG_NFILE"],
    "uC/OS":     [b"uCOS", b"OSTaskCreate", b"OSTimeDly", b"OSStart"],
    "embOS":     [b"embOS", b"OS_CreateTask", b"OS_Start"],
    "RTX":       [b"RTX", b"osKernelStart", b"osThreadNew", b"cmsis_os"],
    "SafeRTOS":  [b"SafeRTOS", b"xSafeRTOS"],
}


def fingerprint_rtos(data: bytes) -> dict:
    """Score binary against known RTOS signatures."""
    matches: dict[str, list[str]] = {}
    for rtos, sigs in _RTOS_SIGNATURES.items():
        found = [s.decode(errors="replace") for s in sigs if s in data]
        if found:
            matches[rtos] = found

    if not matches:
        return {"detected": None, "candidates": {}, "confidence_score": 0.0}

    best = max(matches, key=lambda k: len(matches[k]))
    n_matched = len(matches[best])
    n_total   = len(_RTOS_SIGNATURES[best])
    return {
        "detected":        best,
        "confidence":      f"{n_matched}/{n_total} signatures",
        "confidence_score": round(n_matched / n_total, 2),
        "candidates":      {k: v for k, v in matches.items()},
    }
