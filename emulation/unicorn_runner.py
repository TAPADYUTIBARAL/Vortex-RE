"""
Stage 3c — Unicorn engine snippet emulator.

Lifts individual high-priority functions from baremetal / RTOS targets
into Unicorn, maps them, and hunts for stack pivots or PC hijacks.
"""

import re
import struct
from typing import List, Optional

from models import Finding


# Memory layout constants for emulation
CODE_BASE  = 0x10000
STACK_BASE = 0x70000
STACK_SIZE = 0x10000
HEAP_BASE  = 0x80000
HEAP_SIZE  = 0x10000


def run_unicorn(info, candidate: Finding, triage, timeout: int = 30) -> List[Finding]:
    """
    Lift the function at candidate.address into Unicorn and fuzz its input.
    Returns a list of dynamic Findings on crash/PC hijack.
    """
    try:
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_ARM, UC_ARCH_MIPS
        from unicorn import UC_MODE_MIPS32, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
        from unicorn import UcError, UC_ERR_FETCH_UNMAPPED, UC_ERR_READ_UNMAPPED
        from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
    except ImportError:
        return []

    if not candidate.address or candidate.address in ("?", ""):
        return []

    try:
        target_addr = int(candidate.address, 16)
    except (ValueError, TypeError):
        return []

    arch = triage.arch
    uc, regs = _init_unicorn(arch, triage)
    if not uc:
        return []

    # Map binary code into emulator
    raw = info.raw_bytes
    code_len = min(len(raw), 0x100000)
    load_addr = triage.load_address or CODE_BASE

    try:
        from unicorn import UC_PROT_ALL
        uc.mem_map(load_addr, _align(code_len))
        uc.mem_write(load_addr, raw[:code_len])
        # Map stack
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.reg_write(regs["sp"], STACK_BASE + STACK_SIZE // 2)
        # Map heap area for write targets
        uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    except Exception:
        return []

    findings = []

    # Fuzz: try cyclic inputs of varying sizes
    for size in (64, 128, 256, 512):
        payload = _cyclic_bytes(size)
        try:
            # Write payload to stack input buffer
            sp = uc.reg_read(regs["sp"])
            buf_addr = sp - size - 32
            uc.mem_write(buf_addr, payload)
            uc.reg_write(regs["arg0"] if "arg0" in regs else regs["sp"], buf_addr)
        except Exception:
            continue

        hijacked_pc = None
        sp_clobber  = False

        def _hook_invalid(uc_inst, access, address, size, value, user_data):
            # Called on unmapped memory access — note the address
            pass

        try:
            from unicorn import UC_HOOK_MEM_INVALID
            # Emulate from target address for max 10000 instructions
            uc.emu_start(target_addr, target_addr + 0x2000, timeout=timeout * 1000000,
                         count=10000)
        except Exception as exc:
            exc_str = str(exc)
            # Check if PC was hijacked to our cyclic pattern territory
            try:
                pc_val = uc.reg_read(regs["pc"])
                pc_bytes = struct.pack("<I", pc_val & 0xFFFFFFFF)
                if b"AAAA" in payload or pc_bytes in payload:
                    hijacked_pc = hex(pc_val)
            except Exception:
                pass

        if hijacked_pc:
            # Try to find offset
            sp_val = uc.reg_read(regs.get("sp", 0)) if "sp" in regs else 0
            offset = _estimate_offset(payload, hijacked_pc)
            findings.append(Finding(
                id="",
                stage="dynamic",
                title=f"Unicorn PC hijack: {candidate.function_name or candidate.address}",
                cwe=candidate.cwe or "CWE-120",
                severity="CRITICAL",
                component=candidate.component,
                evidence=(f"Unicorn emulation: PC hijacked to {hijacked_pc} "
                          f"with {size}-byte cyclic payload. "
                          f"Offset estimate: {offset if offset >= 0 else '?'}"),
                confirmation="PLAUSIBLE",
                emulation_trace=(f"arch={arch}  target={candidate.address}  "
                                 f"payload_size={size}  hijacked_pc={hijacked_pc}"),
                exploit_score=0.85,
                address=candidate.address,
                function_name=candidate.function_name,
                manual_steps=[
                    f"Load binary into Unicorn at {hex(load_addr)}",
                    f"Map stack at {hex(STACK_BASE)}",
                    f"Write {size}-byte cyclic pattern as function argument",
                    f"Emulate from {candidate.address}",
                    f"Observe PC = {hijacked_pc} → controlled",
                ],
                runtime_flag="PLAUSIBLE_UNEMULATED",
                runtime_test_hint=f"Confirm PC hijack on real target with GDB; offset ~{offset}",
            ))
            break

    return findings


def _init_unicorn(arch: str, triage):
    """Initialise Unicorn context for target architecture."""
    try:
        from unicorn import Uc
        from unicorn import (
            UC_ARCH_ARM,  UC_MODE_ARM,   UC_MODE_THUMB,
            UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN,
            UC_ARCH_X86,  UC_MODE_32,    UC_MODE_64,
        )
        from unicorn.arm_const  import UC_ARM_REG_PC,  UC_ARM_REG_SP,  UC_ARM_REG_LR, UC_ARM_REG_R0
        from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP, UC_MIPS_REG_A0
        from unicorn.x86_const  import UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EDI
        from unicorn.x86_const  import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RDI
    except ImportError:
        return None, {}

    endian_mode = 0
    if hasattr(__import__("unicorn"), "UC_MODE_BIG_ENDIAN") and triage.endian == "big":
        from unicorn import UC_MODE_BIG_ENDIAN
        endian_mode = UC_MODE_BIG_ENDIAN

    try:
        if arch == "arm":
            bits = triage.bits
            mode = UC_MODE_THUMB if bits == "16" else UC_MODE_ARM
            uc = Uc(UC_ARCH_ARM, mode | endian_mode)
            regs = {"pc": UC_ARM_REG_PC, "sp": UC_ARM_REG_SP, "arg0": UC_ARM_REG_R0}
        elif arch in ("mips",):
            uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | endian_mode)
            regs = {"pc": UC_MIPS_REG_PC, "sp": UC_MIPS_REG_SP, "arg0": UC_MIPS_REG_A0}
        elif arch in ("x86", "x86_64"):
            if triage.bits == "64":
                uc = Uc(UC_ARCH_X86, UC_MODE_64)
                regs = {"pc": UC_X86_REG_RIP, "sp": UC_X86_REG_RSP, "arg0": UC_X86_REG_RDI}
            else:
                uc = Uc(UC_ARCH_X86, UC_MODE_32)
                regs = {"pc": UC_X86_REG_EIP, "sp": UC_X86_REG_ESP, "arg0": UC_X86_REG_EDI}
        else:
            return None, {}
        return uc, regs
    except Exception:
        return None, {}


def _cyclic_bytes(length: int) -> bytes:
    try:
        from pwn import cyclic  # type: ignore
        return cyclic(length)
    except ImportError:
        pattern = b""
        alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        for i in range(length):
            pattern += bytes([alpha[i % len(alpha)]])
        return pattern


def _estimate_offset(payload: bytes, hijacked_pc: str) -> int:
    try:
        pc_int = int(hijacked_pc, 16)
        pc_bytes = struct.pack("<I", pc_int & 0xFFFFFFFF)
        idx = payload.find(pc_bytes)
        return idx
    except Exception:
        return -1


def _align(size: int, page: int = 0x1000) -> int:
    return ((size + page - 1) // page) * page
