"""
Format detection and parsing for bin, hex, dfu, elf, pe files.
"""
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional
from intelhex import IntelHex


@dataclass
class BinaryInfo:
    format: str                    # "raw_bin", "intel_hex", "dfu_stm32", "dfu_nxp", "elf", "pe"
    path: str
    size: int
    raw_bytes: bytes               # extracted binary payload
    architecture: Optional[str] = None
    load_address: Optional[int] = None
    metadata: dict = field(default_factory=dict)
    segments: list = field(default_factory=list)  # list of (addr, data) tuples


_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_IHEX_START = ord(":")
_DFU_SIGNATURE = b"UFD"           # bytes -5:-2 of DFU suffix
_DFUSE_SIGNATURE = b"DfuSe"       # STM32 DfuSe extension marker at offset 0


_ELF_MACHINES = {
    0x00: "unknown", 0x02: "sparc", 0x03: "x86", 0x08: "mips",
    0x14: "powerpc", 0x16: "s390", 0x28: "arm", 0x2a: "superh",
    0x32: "ia-64", 0x3e: "x86_64", 0x40: "aarch64", 0xb7: "aarch64",
    0xf3: "riscv",
}


def detect_and_parse(path: str) -> BinaryInfo:
    with open(path, "rb") as f:
        raw = f.read()

    ext = os.path.splitext(path)[1].lower()

    if raw[:4] == _ELF_MAGIC:
        return _parse_elf(path, raw)

    if raw[:2] == _PE_MAGIC:
        return _parse_pe(path, raw)

    if len(raw) >= 16 and raw[-5:-2] == _DFU_SIGNATURE:
        return _parse_dfu(path, raw)

    if len(raw) > 0 and raw[0] == _IHEX_START:
        return _parse_ihex(path, raw)

    if ext in (".hex",):
        return _parse_ihex(path, raw)

    return _parse_raw_bin(path, raw)


# ── ELF ──────────────────────────────────────────────────────────────────────

def _parse_elf(path: str, raw: bytes) -> BinaryInfo:
    ei_class = raw[4]          # 1 = 32-bit, 2 = 64-bit
    ei_data  = raw[5]          # 1 = LE, 2 = BE
    endian   = "<" if ei_data == 1 else ">"

    if ei_class == 1:
        e_machine = struct.unpack_from(endian + "H", raw, 18)[0]
        e_entry   = struct.unpack_from(endian + "I", raw, 24)[0]
        e_phoff   = struct.unpack_from(endian + "I", raw, 28)[0]
        e_phnum   = struct.unpack_from(endian + "H", raw, 44)[0]
        ph_fmt, ph_size = endian + "IIIIIIII", 32
    else:
        e_machine = struct.unpack_from(endian + "H", raw, 18)[0]
        e_entry   = struct.unpack_from(endian + "Q", raw, 24)[0]
        e_phoff   = struct.unpack_from(endian + "Q", raw, 32)[0]
        e_phnum   = struct.unpack_from(endian + "H", raw, 56)[0]
        ph_fmt, ph_size = endian + "IIQQQQQQ", 56

    arch = _ELF_MACHINES.get(e_machine, f"machine_0x{e_machine:04x}")
    if ei_class == 2 and arch == "arm":
        arch = "aarch64"

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * ph_size
        if ei_class == 1:
            p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(endian + "IIIII", raw, off)
        else:
            p_type   = struct.unpack_from(endian + "I", raw, off)[0]
            p_offset = struct.unpack_from(endian + "Q", raw, off + 8)[0]
            p_vaddr  = struct.unpack_from(endian + "Q", raw, off + 16)[0]
            p_filesz = struct.unpack_from(endian + "Q", raw, off + 32)[0]
        if p_type == 1 and p_filesz > 0:   # PT_LOAD
            segments.append((p_vaddr, raw[p_offset: p_offset + p_filesz]))

    bits = 32 if ei_class == 1 else 64
    endian_name = "little-endian" if ei_data == 1 else "big-endian"
    return BinaryInfo(
        format="elf",
        path=path,
        size=len(raw),
        raw_bytes=raw,
        architecture=arch,
        load_address=e_entry,
        segments=segments,
        metadata={
            "bits": bits,
            "endian": endian_name,
            "entry_point": hex(e_entry),
            "num_segments": len(segments),
        },
    )


# ── PE / EXE ─────────────────────────────────────────────────────────────────

def _parse_pe(path: str, raw: bytes) -> BinaryInfo:
    try:
        import pefile
        pe = pefile.PE(data=raw, fast_load=False)
        machine = pe.FILE_HEADER.Machine
        _pe_machines = {
            0x014c: "x86", 0x8664: "x86_64", 0x01c0: "arm",
            0xaa64: "aarch64", 0x0200: "ia-64",
        }
        arch = _pe_machines.get(machine, f"machine_0x{machine:04x}")
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode(errors="replace"))
        sections = [s.Name.decode(errors="replace").strip("\x00") for s in pe.sections]
        return BinaryInfo(
            format="pe",
            path=path,
            size=len(raw),
            raw_bytes=raw,
            architecture=arch,
            load_address=ep,
            metadata={
                "entry_point": hex(ep),
                "imports": imports,
                "sections": sections,
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            },
        )
    except Exception as exc:
        return BinaryInfo(
            format="pe",
            path=path,
            size=len(raw),
            raw_bytes=raw,
            metadata={"parse_error": str(exc)},
        )


# ── Intel HEX ────────────────────────────────────────────────────────────────

def _parse_ihex(path: str, raw: bytes) -> BinaryInfo:
    ih = IntelHex()
    try:
        ih.loadhex(path)
    except Exception:
        ih.loadbin(path)   # fallback

    segments = []
    for start, end in ih.segments():
        data = bytes(ih.tobinarray(start=start, end=end - 1))
        segments.append((start, data))

    flat = ih.tobinarray()
    binary = bytes(flat)
    min_addr = ih.minaddr() if ih.addresses() else 0

    return BinaryInfo(
        format="intel_hex",
        path=path,
        size=len(raw),
        raw_bytes=binary,
        load_address=min_addr,
        segments=segments,
        metadata={
            "load_address": hex(min_addr),
            "max_address": hex(ih.maxaddr()) if ih.addresses() else "0x0",
            "num_segments": len(segments),
            "total_data_bytes": len(binary),
        },
    )


# ── DFU ──────────────────────────────────────────────────────────────────────

def _parse_dfu(path: str, raw: bytes) -> BinaryInfo:
    # DFU suffix (last 16 bytes)
    suffix = raw[-16:]
    bcd_device  = struct.unpack_from("<H", suffix, 0)[0]
    id_product  = struct.unpack_from("<H", suffix, 2)[0]
    id_vendor   = struct.unpack_from("<H", suffix, 4)[0]
    bcd_dfu     = struct.unpack_from("<H", suffix, 6)[0]
    dfu_sig     = suffix[8:11]   # "UFD"
    suffix_len  = suffix[11]
    crc_stored  = struct.unpack_from("<I", suffix, 12)[0]
    crc_calc    = zlib.crc32(raw[:-4]) & 0xFFFFFFFF

    meta = {
        "vid": hex(id_vendor),
        "pid": hex(id_product),
        "bcd_device": hex(bcd_device),
        "bcd_dfu": hex(bcd_dfu),
        "suffix_length": suffix_len,
        "crc_valid": crc_calc == crc_stored,
    }

    # Check for STM32 DfuSe extension (starts with "DfuSe\x00")
    if raw[:5] == _DFUSE_SIGNATURE:
        return _parse_dfuse(path, raw, meta)

    # Plain DFU: payload is everything before the suffix
    payload = raw[:-16]
    fmt = "dfu_nxp" if id_vendor == 0x1FC9 else "dfu_standard"
    return BinaryInfo(
        format=fmt,
        path=path,
        size=len(raw),
        raw_bytes=payload,
        architecture="arm",     # DFU is almost always ARM for MCUs
        metadata=meta,
    )


def _parse_dfuse(path: str, raw: bytes, dfu_meta: dict) -> BinaryInfo:
    # DfuSe prefix: 11 bytes
    # signature(5) + bVersion(1) + DFUImageSize(4) + bTargets(1)
    b_targets = raw[10]
    segments = []
    offset = 11

    for t in range(b_targets):
        # Target prefix: 274 bytes
        # szTargetSignature(6) + bAlternateSetting(1) + bTargetNamed(4) + ...
        # szTargetName(255) + dwTagetSize(4) + dwNbElements(4)
        if offset + 274 > len(raw) - 16:
            break
        nb_elements = struct.unpack_from("<I", raw, offset + 270)[0]
        offset += 274

        for _ in range(nb_elements):
            if offset + 8 > len(raw) - 16:
                break
            elem_addr = struct.unpack_from("<I", raw, offset)[0]
            elem_size = struct.unpack_from("<I", raw, offset + 4)[0]
            offset += 8
            elem_data = raw[offset: offset + elem_size]
            offset += elem_size
            segments.append((elem_addr, elem_data))

    flat = b"".join(d for _, d in segments)
    load_addr = segments[0][0] if segments else None

    dfu_meta.update({
        "format": "DfuSe (STM32)",
        "num_targets": b_targets,
        "num_elements": len(segments),
        "load_address": hex(load_addr) if load_addr is not None else "unknown",
    })

    return BinaryInfo(
        format="dfu_stm32",
        path=path,
        size=len(raw),
        raw_bytes=flat,
        architecture="arm",      # STM32 = Cortex-M (ARM Thumb-2)
        load_address=load_addr,
        segments=segments,
        metadata=dfu_meta,
    )


# ── Raw binary ───────────────────────────────────────────────────────────────

def _parse_raw_bin(path: str, raw: bytes) -> BinaryInfo:
    return BinaryInfo(
        format="raw_bin",
        path=path,
        size=len(raw),
        raw_bytes=raw,
        metadata={"note": "No recognized header — treating as raw binary"},
    )
