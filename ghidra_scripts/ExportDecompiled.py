# ExportDecompiled.py — Ghidra headless script
# Decompiles all functions and exports them to JSON.
#
# Usage (analyzeHeadless):
#   -postScript ExportDecompiled.py <output_dir>
#
# Output: <output_dir>/ExportDecompiled.json
#   { "functions": [ { "name", "address", "decompile", "size" }, ... ] }

import json
import os

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_out"
    out_file = os.path.join(out_dir, "ExportDecompiled.json")

    program = currentProgram
    ifc = DecompInterface()
    options = DecompileOptions()
    ifc.setOptions(options)
    ifc.openProgram(program)

    mon = ConsoleTaskMonitor()
    fm  = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))

    results = []
    for fn in funcs:
        if monitor.isCancelled():
            break
        try:
            res = ifc.decompileFunction(fn, 30, mon)
            if res and res.decompileCompleted():
                decomp = res.getDecompiledFunction()
                code = decomp.getC() if decomp else ""
            else:
                code = ""
        except Exception:
            code = ""

        results.append({
            "name":      fn.getName(),
            "address":   str(fn.getEntryPoint()),
            "size":      fn.getBody().getNumAddresses(),
            "decompile": code[:4000],
        })

    try:
        with open(out_file, "w") as fh:
            json.dump({"functions": results}, fh)
        println("ExportDecompiled: wrote %d functions to %s" % (len(results), out_file))
    except Exception as e:
        println("ExportDecompiled error: " + str(e))


run()
