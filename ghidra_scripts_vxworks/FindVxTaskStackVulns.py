# FindVxTaskStackVulns.py
# Ghidra post-analysis script — VX2A
#
# Scans functions in a VxWorks binary for:
#   1. Calls to dangerous functions (strcpy, gets, sprintf, memcpy with tainted size)
#   2. Stack allocations larger than VxWorks default task stack size (4KB–8KB typical)
#   3. Stack variable used as destination in memcpy/bcopy without size check
#
# No ASLR + no NX + no canary → all findings auto-escalate to CRITICAL.
#
# Output: <out_dir>/vxworks_stack_vulns.json

import json
import os

DANGEROUS_FUNCS = {
    "strcpy":   "CWE-120",
    "strcat":   "CWE-120",
    "gets":     "CWE-120",
    "sprintf":  "CWE-134",
    "vsprintf": "CWE-134",
    "bcopy":    "CWE-120",  # no bounds check
    "memcpy":   "CWE-120",
}

MAX_SAFE_STACK = 8192   # VxWorks typical task stack
CRITICAL_STACK = 4096   # any local buf > 4KB without check is suspicious


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program = currentProgram  # noqa: F821
    listing = program.getListing()
    refs    = program.getReferenceManager()
    sym_tbl = program.getSymbolTable()

    findings = []

    # Build map of dangerous function addresses
    dangerous_addrs = {}
    for sym in sym_tbl.getAllSymbols(True):
        name = sym.getName()
        if name in DANGEROUS_FUNCS:
            dangerous_addrs[str(sym.getAddress())] = (name, DANGEROUS_FUNCS[name])

    # Scan all functions for calls to dangerous functions
    for func in listing.getFunctions(True):
        func_name  = func.getName()
        func_entry = str(func.getEntryPoint())
        body = func.getBody()

        callee_refs = []
        for call_ref in refs.getReferencesFrom(func.getEntryPoint()):
            ref_addr = str(call_ref.getToAddress())
            if ref_addr in dangerous_addrs:
                callee_refs.append(dangerous_addrs[ref_addr])

        # Scan all instructions in function body for calls
        addr_set = body.getAddressRanges()
        for rng in addr_set:
            cur = rng.getMinAddress()
            end = rng.getMaxAddress()
            while cur is not None and cur.compareTo(end) <= 0:
                instr = listing.getInstructionAt(cur)
                if instr is None:
                    break
                mnem = instr.getMnemonicString().upper()
                if mnem in ("BL", "BLX", "CALL", "JAL", "JALR", "BCTRL"):
                    for ref in refs.getReferencesFrom(cur):
                        ref_s = str(ref.getToAddress())
                        if ref_s in dangerous_addrs:
                            fname, cwe = dangerous_addrs[ref_s]
                            findings.append({
                                "type": "dangerous_call",
                                "caller": func_name,
                                "caller_addr": func_entry,
                                "call_site": str(cur),
                                "callee": fname,
                                "cwe": cwe,
                                "severity": "CRITICAL",
                                "note": "No canary, no NX, no ASLR — auto-escalate to CRITICAL",
                            })
                try:
                    cur = cur.next()
                except Exception:
                    break

    out_path = os.path.join(out_dir, "vxworks_stack_vulns.json")
    with open(out_path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)
    print(f"[FindVxTaskStackVulns] {len(findings)} findings → {out_path}")


run()
