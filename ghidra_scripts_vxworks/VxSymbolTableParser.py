# VxSymbolTableParser.py
# Ghidra post-analysis script — runs AFTER vxhunter_ghidra.py
#
# Reads the symbols JSON produced by vxhunter (or symbol_parser.py heuristic)
# and exports a cleaned JSON mapping {address: name} plus per-function metadata.
#
# Usage (headless):
#   -postScript VxSymbolTableParser.py <out_dir> <symbols_json>
#
# Output: <out_dir>/vxworks_symbols_ghidra.json

import json
import os

from ghidra.program.model.symbol import SymbolType  # type: ignore
from ghidra.program.model.listing import CodeUnit    # type: ignore


def run():
    args = getScriptArgs()
    out_dir     = args[0] if len(args) > 0 else "/tmp/ghidra_vx"
    symbols_json = args[1] if len(args) > 1 else os.path.join(out_dir, "vxworks_symbols.json")

    os.makedirs(out_dir, exist_ok=True)

    program  = currentProgram  # noqa: F821
    listing  = program.getListing()
    addr_fac = program.getAddressFactory()
    sym_tbl  = program.getSymbolTable()

    # Load external symbols from vxhunter/heuristic JSON
    ext_symbols = []
    if os.path.isfile(symbols_json):
        with open(symbols_json) as f:
            data = json.load(f)
        ext_symbols = data.get("symbols", [])
        print(f"[VxSymbolTableParser] Loaded {len(ext_symbols)} external symbols")

    # Apply external symbols to Ghidra program
    applied = 0
    for sym in ext_symbols:
        name = sym.get("name", "")
        addr_str = sym.get("address", "")
        if not name or not addr_str:
            continue
        try:
            addr = addr_fac.getAddress(addr_str)
            if addr is None:
                continue
            existing = sym_tbl.getSymbol(name, addr, None)
            if existing is None:
                sym_tbl.createLabel(addr, name, ghidra.program.model.symbol.SourceType.IMPORTED)  # noqa: F821
                applied += 1
        except Exception as exc:
            print(f"[VxSymbolTableParser] Warning: {name}@{addr_str}: {exc}")

    print(f"[VxSymbolTableParser] Applied {applied} symbols to Ghidra DB")

    # Export Ghidra function list with addresses
    functions = []
    for func in listing.getFunctions(True):
        entry = str(func.getEntryPoint())
        name  = func.getName()
        size  = func.getBody().getNumAddresses()
        functions.append({
            "address": entry,
            "name": name,
            "size": size,
        })

    out = {
        "program": str(program.getName()),
        "function_count": len(functions),
        "symbol_count": len(ext_symbols),
        "functions": functions,
    }

    out_path = os.path.join(out_dir, "vxworks_symbols_ghidra.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[VxSymbolTableParser] Wrote {out_path}")


run()
