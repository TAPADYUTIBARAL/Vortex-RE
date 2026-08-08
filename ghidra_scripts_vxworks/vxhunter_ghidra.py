# vxhunter_ghidra.py — Headless-compatible VxWorks symbol annotation
# @author re_agent
# @category VxWorks
#
# Runs vxhunter symbol extraction INSIDE Ghidra's memory model, then applies
# all recovered symbols as IMPORTED labels.  Runs before VxSymbolTableParser.py.
#
# This script is headless-safe: no askChoice(), no GUI popups.
#
# Usage (headless):
#   -postScript vxhunter_ghidra.py <out_dir>
#
# Output: <out_dir>/vxhunter_ghidra_symbols.json  (for diagnostics)
#
# Note: written for Jython (Python 2.7) — Ghidra's scripting engine.
#   No f-strings, no type hints, no Python 3-only builtins.

import json
import os
import sys

from ghidra.program.model.symbol import SourceType   # type: ignore
from ghidra.program.model.listing import CodeUnit     # type: ignore
from ghidra.util.task import ConsoleTaskMonitor       # type: ignore


def _find_vxhunter_path():
    """Return path to vxhunter firmware_tools dir, or None."""
    candidates = [
        os.environ.get("VXHUNTER_PATH", ""),
        os.path.expanduser("~/vxhunter/firmware_tools"),
        "/opt/vxhunter/firmware_tools",
    ]
    for p in candidates:
        if p and os.path.isfile(os.path.join(p, "vxhunter_core_py3.py")):
            return p
        if p and os.path.isfile(os.path.join(p, "vxhunter_core.py")):
            return p
    return None


def _import_vxtarget(vxhunter_path):
    """Import VxTarget from vxhunter firmware_tools directory."""
    if vxhunter_path not in sys.path:
        sys.path.insert(0, vxhunter_path)
    try:
        from vxhunter_core_py3 import VxTarget  # type: ignore
        return VxTarget
    except ImportError:
        pass
    try:
        from vxhunter_core import VxTarget  # type: ignore
        return VxTarget
    except ImportError:
        return None


def _read_program_bytes(program):
    """Read all initialised memory from the Ghidra program into a bytearray."""
    mem = program.getMemory()
    buf = bytearray()
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        size = block.getSize()
        data = bytearray(size)
        block.getBytes(block.getStart(), data, 0, size)
        buf.extend(data)
    return bytes(buf)


def _try_extract(VxTarget, firmware, vx_version, is_big_endian):
    """Run vxhunter extraction for one (version, endian) combination."""
    try:
        target = VxTarget(
            firmware=firmware,
            vx_version=vx_version,
            is_big_endian=is_big_endian,
        )
        target.find_loading_address()
        target.find_symbol_table()
        syms = target.get_symbols()
        if syms:
            return syms, target.load_address
    except Exception as exc:
        print("[vxhunter_ghidra] attempt vx=" + str(vx_version)
              + " big_endian=" + str(is_big_endian) + " failed: " + str(exc))
    return None, None


def _apply_symbols(sym_tbl, addr_fac, fm, symbols):
    """Apply a list of {name, address} dicts to Ghidra's symbol table."""
    applied = 0
    functions_created = 0
    for sym in symbols:
        name = sym.get("name", "")
        addr_val = sym.get("address", 0)
        sym_type = sym.get("type", 0)
        if not name:
            continue
        # addr_val may be int or hex string
        if isinstance(addr_val, int):
            addr_hex = hex(addr_val).rstrip("L")
        else:
            addr_hex = str(addr_val)
        try:
            addr = addr_fac.getAddress(addr_hex)
            if addr is None:
                continue
            existing = sym_tbl.getSymbol(name, addr, None)
            if existing is None:
                sym_tbl.createLabel(addr, name, SourceType.IMPORTED)
                applied += 1
            # sym_type 0x04/0x05 = function in VxWorks symbol table
            if sym_type in (0x04, 0x05, 4, 5):
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    try:
                        fm.createFunction(name, addr,
                                          fm.getFunctionAt(addr),
                                          SourceType.IMPORTED)
                        functions_created += 1
                    except Exception:
                        pass
        except Exception as exc:
            print("[vxhunter_ghidra] label error " + name
                  + "@" + addr_hex + ": " + str(exc))
    return applied, functions_created


def run():
    args = getScriptArgs()  # noqa: F821  (Ghidra global)
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program  = currentProgram   # noqa: F821
    addr_fac = program.getAddressFactory()
    sym_tbl  = program.getSymbolTable()
    fm       = program.getFunctionManager()

    print("[vxhunter_ghidra] Starting headless VxWorks symbol extraction")

    vxhunter_path = _find_vxhunter_path()
    if not vxhunter_path:
        print("[vxhunter_ghidra] vxhunter not found — "
              "set VXHUNTER_PATH or clone to ~/vxhunter. Skipping.")
        return

    VxTarget = _import_vxtarget(vxhunter_path)
    if VxTarget is None:
        print("[vxhunter_ghidra] Could not import VxTarget. Skipping.")
        return

    # Read firmware bytes from Ghidra (more accurate than re-reading the file)
    print("[vxhunter_ghidra] Reading program memory...")
    firmware = _read_program_bytes(program)
    print("[vxhunter_ghidra] Read " + str(len(firmware)) + " bytes from program memory")

    # Try all four combinations: (vx_version, endianness)
    candidates = [
        (5, False),  # VxWorks 5.x little-endian (most ARM)
        (5, True),   # VxWorks 5.x big-endian (PPC/MIPS classic)
        (6, False),  # VxWorks 6.x little-endian
        (6, True),   # VxWorks 6.x big-endian
    ]

    best_syms = None
    best_load_addr = None

    for vx_ver, big_endian in candidates:
        syms, load_addr = _try_extract(VxTarget, firmware, vx_ver, big_endian)
        if syms:
            print("[vxhunter_ghidra] Found " + str(len(syms))
                  + " symbols (vx=" + str(vx_ver)
                  + " big_endian=" + str(big_endian)
                  + " load_addr=" + str(hex(load_addr) if load_addr else "?") + ")")
            if best_syms is None or len(syms) > len(best_syms):
                best_syms = syms
                best_load_addr = load_addr

    if not best_syms:
        print("[vxhunter_ghidra] No symbols found by vxhunter in any combination.")
        print("[vxhunter_ghidra] VxSymbolTableParser.py will use symbols from VX1b JSON instead.")
        return

    print("[vxhunter_ghidra] Applying " + str(len(best_syms)) + " symbols to Ghidra DB...")
    applied, fns = _apply_symbols(sym_tbl, addr_fac, fm, best_syms)
    print("[vxhunter_ghidra] Applied " + str(applied) + " labels, "
          + str(fns) + " functions created")

    # Write diagnostics JSON
    diag = {
        "symbol_count": len(best_syms),
        "applied": applied,
        "functions_created": fns,
        "load_address": hex(best_load_addr) if best_load_addr else None,
        "symbols": [
            {"name": s.get("name", ""), "address": hex(s.get("address", 0))}
            for s in best_syms[:200]   # cap for file size
        ],
    }
    diag_path = os.path.join(out_dir, "vxhunter_ghidra_symbols.json")
    with open(diag_path, "w") as f:
        json.dump(diag, f, indent=2)
    print("[vxhunter_ghidra] Wrote " + diag_path)
    print("[vxhunter_ghidra] Done.")


run()
