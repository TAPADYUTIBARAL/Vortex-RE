"""
VxWorks Unicorn emulation runner — Stage VX3b.

Differences from the Linux unicorn_runner:
  - QEMU user-mode is not available; Unicorn fills that role entirely
  - VxWorks API stubs must be implemented (not just NOP'd)
    because downstream logic reads their results (bcopy/bzero copy real memory)
  - Architecture-conditional register constants (PPC, MIPS, ARM, x86)
  - No Linux syscall hooks needed; instead hook common VxWorks libc calls

Architecture support:
  arm   — UC_ARCH_ARM  / UC_MODE_ARM
  ppc   — UC_ARCH_PPC  / UC_MODE_PPC32 | BIG_ENDIAN
  mips  — UC_ARCH_MIPS / UC_MODE_MIPS32 | BIG_ENDIAN
  x86   — UC_ARCH_X86  / UC_MODE_32
"""

import struct
from typing import Callable, Optional

try:
    from unicorn import (Uc, UC_ARCH_ARM, UC_ARCH_PPC, UC_ARCH_MIPS, UC_ARCH_X86,
                          UC_MODE_ARM, UC_MODE_PPC32, UC_MODE_MIPS32, UC_MODE_32,
                          UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
                          UC_HOOK_INSN_INVALID, UcError)
    from unicorn.arm_const  import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
    from unicorn.ppc_const  import UC_PPC_REG_3 as UC_PPC_REG_R3, UC_PPC_REG_4 as UC_PPC_REG_R4, UC_PPC_REG_5 as UC_PPC_REG_R5, UC_PPC_REG_PC, UC_PPC_REG_1 as UC_PPC_REG_SP, UC_PPC_REG_LR
    from unicorn.mips_const import UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_V0, UC_MIPS_REG_PC, UC_MIPS_REG_SP, UC_MIPS_REG_RA
    from unicorn.x86_const  import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


# ── Architecture configuration table ─────────────────────────────────────────
# (arch_const, mode_const, ret_reg, pc_reg, sp_reg, arg0_reg, arg1_reg, arg2_reg)

def _ARCH_CONFIG():
    if not UNICORN_AVAILABLE:
        return {}
    return {
        "arm": (
            UC_ARCH_ARM, UC_MODE_ARM,
            UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_SP,
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        ),
        "ppc": (
            UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN,
            UC_PPC_REG_R3, UC_PPC_REG_PC, UC_PPC_REG_SP,
            UC_PPC_REG_R3, UC_PPC_REG_R4, UC_PPC_REG_R5,
        ),
        "mips": (
            UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
            UC_MIPS_REG_V0, UC_MIPS_REG_PC, UC_MIPS_REG_SP,
            UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2,
        ),
        "x86": (
            UC_ARCH_X86, UC_MODE_32,
            UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP,
            UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
        ),
    }


# ── VxWorks API stub addresses (mapped to a stub page) ───────────────────────

STUB_BASE = 0xDEAD0000
STUB_PAGE_SIZE = 0x1000

_STUBS = {
    # libc-like
    "bcopy":           STUB_BASE + 0x00,
    "bzero":           STUB_BASE + 0x10,
    "memcpy":          STUB_BASE + 0x20,
    "memset":          STUB_BASE + 0x30,
    "strlen":          STUB_BASE + 0x40,
    "strcpy":          STUB_BASE + 0x50,
    "strncpy":         STUB_BASE + 0x60,
    "strcmp":          STUB_BASE + 0x70,
    "strncmp":         STUB_BASE + 0x80,
    "sprintf":         STUB_BASE + 0x90,
    "snprintf":        STUB_BASE + 0xA0,
    # VxWorks task/sync API
    "taskDelay":       STUB_BASE + 0x100,
    "semTake":         STUB_BASE + 0x110,
    "semGive":         STUB_BASE + 0x120,
    "semCreate":       STUB_BASE + 0x130,
    "semBCreate":      STUB_BASE + 0x140,
    "semMCreate":      STUB_BASE + 0x150,
    "msgQSend":        STUB_BASE + 0x160,
    "msgQReceive":     STUB_BASE + 0x170,
    "intLock":         STUB_BASE + 0x180,
    "intUnlock":       STUB_BASE + 0x190,
    # Timing
    "sysClkRateGet":   STUB_BASE + 0x200,
    "tickGet":         STUB_BASE + 0x210,
    # Network buffer (mbuf)
    "netMblkGet":      STUB_BASE + 0x300,
    "netBufLib":       STUB_BASE + 0x310,
    "mBlkGet":         STUB_BASE + 0x320,
    # Memory
    "malloc":          STUB_BASE + 0x400,
    "free":            STUB_BASE + 0x410,
    "calloc":          STUB_BASE + 0x420,
    "realloc":         STUB_BASE + 0x430,
    # I/O
    "printf":          STUB_BASE + 0x500,
    "logMsg":          STUB_BASE + 0x510,
    "write":           STUB_BASE + 0x520,
    "read":            STUB_BASE + 0x530,
    "open":            STUB_BASE + 0x540,
    "close":           STUB_BASE + 0x550,
}


def _build_return_stub(arch: str) -> bytes:
    """Build minimal return instruction for the given architecture."""
    if arch == "arm":
        # BX LR
        return b"\x1e\xff\x2f\xe1"
    if arch == "ppc":
        # BLR (branch to link register)
        return b"\x4e\x80\x00\x20"
    if arch == "mips":
        # JR RA; NOP
        return b"\x03\xe0\x00\x08" + b"\x00\x00\x00\x00"
    if arch == "x86":
        # RETN
        return b"\xc3"
    return b"\xc3"


class VxWorksUnicornRunner:
    """Unicorn emulation engine with VxWorks API stubs."""

    def __init__(self, firmware_path: str, load_addr: int, arch: str = "arm",
                 symbols: Optional[list] = None):
        if not UNICORN_AVAILABLE:
            raise RuntimeError("unicorn not installed: pip install unicorn")

        self.firmware_path = firmware_path
        self.load_addr = load_addr
        self.arch = arch.lower()
        self.symbols = symbols or []

        cfg = _ARCH_CONFIG().get(self.arch)
        if cfg is None:
            raise ValueError(f"Unsupported arch: {self.arch}")

        (arch_c, mode_c,
         self._ret_reg, self._pc_reg, self._sp_reg,
         self._arg0, self._arg1, self._arg2) = cfg

        with open(firmware_path, "rb") as f:
            self._firmware = f.read()

        self._uc = Uc(arch_c, mode_c)
        self._traces: list[str] = []
        self._crash: Optional[str] = None
        self._stub_addrs: set[int] = set()

        self._setup_memory()
        self._install_stubs()
        self._install_symbol_stubs()
        self._install_hooks()

    def _setup_memory(self):
        """Map firmware and a stack region."""
        fw_size = (len(self._firmware) + 0xFFF) & ~0xFFF
        self._uc.mem_map(self.load_addr, max(fw_size, 0x100000))
        self._uc.mem_write(self.load_addr, self._firmware)

        # Stack: 1MB at 0x10000000
        self._stack_base = 0x10000000
        self._uc.mem_map(self._stack_base, 0x100000)
        sp = self._stack_base + 0x80000  # middle of stack
        self._uc.reg_write(self._sp_reg, sp)

        # Stub page
        self._uc.mem_map(STUB_BASE, STUB_PAGE_SIZE)
        ret_stub = _build_return_stub(self.arch)
        for offset in range(0, STUB_PAGE_SIZE, len(ret_stub)):
            self._uc.mem_write(STUB_BASE + offset, ret_stub)

        # Heap: 1MB at 0x20000000 — pre-mapped so _stub_malloc can write immediately
        self._heap_base = 0x20000000
        self._heap_size = 0x100000
        self._heap_ptr  = [self._heap_base]   # instance-level bump pointer
        self._uc.mem_map(self._heap_base, self._heap_size)

    def _install_stubs(self):
        self._stub_addrs = set(_STUBS.values())

    def _install_symbol_stubs(self):
        """Map binary symbol addresses to stub addresses for missing functions."""
        # Build name→addr map from resolved symbols
        self._sym_map: dict[str, int] = {
            s["name"]: int(s["address"], 16) for s in self.symbols if "address" in s
        }

    def _install_hooks(self):
        self._uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self._uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)

    def _hook_code(self, uc, address, size, user_data):
        if address in self._stub_addrs:
            self._handle_stub(uc, address)

    def _handle_stub(self, uc: "Uc", address: int):
        """Dispatch VxWorks API stub by address."""
        name = next((n for n, a in _STUBS.items() if a == address), "unknown")
        self._traces.append(f"stub:{name}@{address:#x}")

        if name == "bcopy":
            # bcopy(src, dst, len) — real copy so callers see results
            self._stub_bcopy(uc)
        elif name == "bzero":
            # bzero(buf, len) — zero memory
            self._stub_bzero(uc)
        elif name == "memcpy":
            self._stub_bcopy(uc)   # same ABI as bcopy
        elif name == "memset":
            self._stub_memset(uc)
        elif name in ("taskDelay", "semTake", "semGive", "intLock", "intUnlock"):
            # No-op — timing/sync not meaningful in emulation
            uc.reg_write(self._ret_reg, 0)
        elif name == "sysClkRateGet":
            uc.reg_write(self._ret_reg, 60)   # 60 Hz typical VxWorks clock
        elif name == "tickGet":
            uc.reg_write(self._ret_reg, 1000)
        elif name in ("malloc", "calloc", "realloc"):
            self._stub_malloc(uc)
        elif name == "free":
            pass  # no-op
        elif name in ("printf", "logMsg", "write"):
            uc.reg_write(self._ret_reg, 0)
        else:
            uc.reg_write(self._ret_reg, 0)

    def _read_mem(self, addr: int, length: int) -> bytes:
        try:
            return bytes(self._uc.mem_read(addr, length))
        except UcError:
            return b"\x00" * length

    def _stub_bcopy(self, uc: "Uc"):
        src = uc.reg_read(self._arg0)
        dst = uc.reg_read(self._arg1)
        n   = uc.reg_read(self._arg2)
        if 0 < n <= 0x10000:
            data = self._read_mem(src, n)
            try:
                uc.mem_write(dst, data)
            except UcError:
                pass
        uc.reg_write(self._ret_reg, dst)

    def _stub_bzero(self, uc: "Uc"):
        buf = uc.reg_read(self._arg0)
        n   = uc.reg_read(self._arg1)
        if 0 < n <= 0x10000:
            try:
                uc.mem_write(buf, b"\x00" * n)
            except UcError:
                pass
        uc.reg_write(self._ret_reg, 0)

    def _stub_memset(self, uc: "Uc"):
        buf = uc.reg_read(self._arg0)
        val = uc.reg_read(self._arg1) & 0xFF
        n   = uc.reg_read(self._arg2)
        if 0 < n <= 0x10000:
            try:
                uc.mem_write(buf, bytes([val]) * n)
            except UcError:
                pass
        uc.reg_write(self._ret_reg, buf)

    def _stub_malloc(self, uc: "Uc"):
        size = uc.reg_read(self._arg0)
        size = max((size + 15) & ~15, 16)
        heap_end = self._heap_base + self._heap_size
        try:
            # Extend heap mapping if current allocation would overflow
            if self._heap_ptr[0] + size >= heap_end:
                extra = 0x100000
                self._uc.mem_map(heap_end, extra)
                self._heap_size += extra
            addr = self._heap_ptr[0]
            self._heap_ptr[0] += size
            uc.reg_write(self._ret_reg, addr)
        except UcError:
            uc.reg_write(self._ret_reg, 0)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        self._crash = f"invalid_mem_access@{address:#x} (access={access})"
        uc.emu_stop()
        return False

    def emulate_function(self, func_addr: int, args: list[int] = None,
                         max_insns: int = 10000) -> dict:
        """
        Emulate a single function at func_addr with given args.
        Returns trace dict.
        """
        self._traces = []
        self._crash = None
        args = args or []

        arg_regs = [self._arg0, self._arg1, self._arg2]
        for i, val in enumerate(args[:3]):
            self._uc.reg_write(arg_regs[i], val)

        try:
            self._uc.emu_start(func_addr, func_addr + 0x1000,
                               count=max_insns)
        except UcError as exc:
            self._crash = str(exc)

        pc = self._uc.reg_read(self._pc_reg)
        ret = self._uc.reg_read(self._ret_reg)

        return {
            "func_addr": hex(func_addr),
            "return_value": hex(ret),
            "final_pc": hex(pc),
            "crash": self._crash,
            "stubs_hit": self._traces,
            "arch": self.arch,
        }

    def emulate_overflow_probe(self, func_addr: int,
                               input_buf_addr: int,
                               pattern: bytes,
                               max_insns: int = 50000) -> dict:
        """
        Write cyclic pattern to input_buf_addr, then emulate func_addr.
        If PC lands in the pattern region, we have a confirmed overflow.
        """
        try:
            self._uc.mem_write(input_buf_addr, pattern)
        except UcError as exc:
            return {"status": "setup_error", "error": str(exc)}

        result = self.emulate_function(func_addr, max_insns=max_insns)

        final_pc = int(result["final_pc"], 16)
        in_pattern = False
        try:
            from pwn import cyclic_find  # type: ignore
            pc_bytes = struct.pack(">I", final_pc)
            offset = cyclic_find(pc_bytes)
            if offset >= 0:
                result["overflow_offset"] = offset
                result["overflow_confirmed"] = True
                in_pattern = True
        except Exception:
            pass

        if not in_pattern and result.get("crash"):
            result["overflow_confirmed"] = True
            result["overflow_offset"] = -1

        result["status"] = "confirmed" if result.get("overflow_confirmed") else "clean"
        return result
