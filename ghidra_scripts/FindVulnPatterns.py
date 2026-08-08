# FindVulnPatterns.py — Ghidra headless script
# Finds dangerous function call sites (strcpy, gets, sprintf, memcpy, etc.)
# and exports them with decompilation context.
#
# Usage: -postScript FindVulnPatterns.py <output_dir>
# Output: <output_dir>/FindVulnPatterns.json

import json
import os

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor


DANGEROUS = [
    ("strcpy",   "CWE-120", 0.8),
    ("strncpy",  "CWE-120", 0.5),
    ("strcat",   "CWE-120", 0.7),
    ("strncat",  "CWE-120", 0.5),
    ("gets",     "CWE-242", 1.0),
    ("sprintf",  "CWE-134", 0.7),
    ("vsprintf", "CWE-134", 0.7),
    ("scanf",    "CWE-134", 0.6),
    ("sscanf",   "CWE-134", 0.5),
    ("memcpy",   "CWE-120", 0.5),
    ("memmove",  "CWE-120", 0.4),
    ("printf",   "CWE-134", 0.4),
    ("alloca",   "CWE-770", 0.4),
    ("system",   "CWE-78",  0.9),
    ("popen",    "CWE-78",  0.9),
    ("execve",   "CWE-78",  0.7),
]


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_out"
    out_file = os.path.join(out_dir, "FindVulnPatterns.json")

    program = currentProgram
    sym_table = program.getSymbolTable()
    listing = program.getListing()

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(program)
    mon = ConsoleTaskMonitor()
    fm  = program.getFunctionManager()

    findings = []

    for fn_name, cwe, score in DANGEROUS:
        # Find all symbols matching this function name
        syms = list(sym_table.getSymbols(fn_name))
        for sym in syms:
            if sym.getSymbolType() not in (SymbolType.FUNCTION, SymbolType.LABEL):
                continue
            # Find all callers of this symbol
            refs = list(sym.getReferences())
            for ref in refs:
                call_addr = ref.getFromAddress()
                caller_fn = fm.getFunctionContaining(call_addr)
                if not caller_fn:
                    continue

                # Decompile caller
                decomp_code = ""
                try:
                    res = ifc.decompileFunction(caller_fn, 20, mon)
                    if res and res.decompileCompleted():
                        dc = res.getDecompiledFunction()
                        decomp_code = dc.getC()[:2000] if dc else ""
                except Exception:
                    pass

                findings.append({
                    "title":    "Dangerous call: %s() in %s" % (fn_name, caller_fn.getName()),
                    "vuln_type": fn_name,
                    "cwe":      cwe,
                    "address":  str(call_addr),
                    "function": caller_fn.getName(),
                    "evidence": "%s() called from %s at %s" % (fn_name, caller_fn.getName(), str(call_addr)),
                    "decompile": decomp_code,
                    "score":    score,
                })

    try:
        with open(out_file, "w") as fh:
            json.dump({"findings": findings}, fh)
        println("FindVulnPatterns: %d findings → %s" % (len(findings), out_file))
    except Exception as e:
        println("FindVulnPatterns error: " + str(e))


run()
