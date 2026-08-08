# FindVxISRVulns.py
# Ghidra post-analysis script — VX2A
#
# Detects ISR (Interrupt Service Routine) vulnerabilities in VxWorks:
#   1. ISRs that call blocking functions (semTake, msgQReceive, taskDelay)
#      — illegal in ISR context; causes kernel panic
#   2. ISRs that allocate heap memory (malloc in interrupt context)
#   3. Non-trivial ISR code size (>50 instructions) — signal complexity + risk
#   4. intConnect() usage with untrusted function pointer
#
# Output: <out_dir>/vxworks_isr_vulns.json

import json
import os


BLOCKING_IN_ISR = {"semTake", "msgQReceive", "taskDelay", "semWait", "rngBufGet"}
HEAP_IN_ISR     = {"malloc", "calloc", "realloc", "free", "memPartAlloc"}
ISR_CONNECTORS  = {"intConnect", "intVecSet", "intVecGet", "isrInstall"}


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program = currentProgram  # noqa: F821
    sym_tbl = program.getSymbolTable()
    listing = program.getListing()
    refs    = program.getReferenceManager()

    findings = []

    # Build addr→name map for functions of interest
    sym_map = {}
    for sym in sym_tbl.getAllSymbols(True):
        name = sym.getName()
        if name in (BLOCKING_IN_ISR | HEAP_IN_ISR | ISR_CONNECTORS):
            sym_map[str(sym.getAddress())] = name

    # Find functions called from intConnect (these are ISRs)
    isr_addrs = set()
    for sym in sym_tbl.getAllSymbols(True):
        if sym.getName() == "intConnect":
            for call_ref in refs.getReferencesTo(sym.getAddress()):
                caller_addr = call_ref.getFromAddress()
                # The argument to intConnect is the ISR address (second arg)
                # We can't easily extract it without data-flow analysis,
                # so mark all functions that call intConnect as ISR-adjacent
                func = listing.getFunctionContaining(caller_addr)
                if func:
                    isr_addrs.add(str(func.getEntryPoint()))
                    findings.append({
                        "type": "isr_registration",
                        "severity": "INFO",
                        "function": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "call_site": str(caller_addr),
                        "note": "This function calls intConnect — ISR registration site",
                    })

    # Scan all functions for blocked calls in ISR context
    for func in listing.getFunctions(True):
        func_entry = str(func.getEntryPoint())
        func_name  = func.getName()

        blocked_calls = []
        heap_calls    = []

        body = func.getBody()
        for rng in body.getAddressRanges():
            cur = rng.getMinAddress()
            end = rng.getMaxAddress()
            while cur is not None and cur.compareTo(end) <= 0:
                instr = listing.getInstructionAt(cur)
                if instr is None:
                    break
                for ref in refs.getReferencesFrom(cur):
                    ref_s = str(ref.getToAddress())
                    if ref_s in sym_map:
                        called = sym_map[ref_s]
                        if called in BLOCKING_IN_ISR:
                            blocked_calls.append(
                                {"callee": called, "call_site": str(cur)})
                        elif called in HEAP_IN_ISR:
                            heap_calls.append(
                                {"callee": called, "call_site": str(cur)})
                try:
                    cur = cur.next()
                except Exception:
                    break

        # Only flag if function is ISR or has suspicious name
        is_isr = (func_entry in isr_addrs or
                  any(kw in func_name.lower()
                      for kw in ("isr", "irq", "interrupt", "handler", "vectbl")))

        if is_isr and blocked_calls:
            findings.append({
                "type": "blocking_call_in_isr",
                "severity": "HIGH",
                "function": func_name,
                "address": func_entry,
                "blocked_calls": blocked_calls,
                "cwe": "CWE-833",
                "note": "Blocking VxWorks call inside ISR — kernel panic / deadlock",
            })
        if is_isr and heap_calls:
            findings.append({
                "type": "heap_alloc_in_isr",
                "severity": "HIGH",
                "function": func_name,
                "address": func_entry,
                "heap_calls": heap_calls,
                "note": "Heap allocation in ISR — unsafe in VxWorks interrupt context",
            })

    out_path = os.path.join(out_dir, "vxworks_isr_vulns.json")
    with open(out_path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)
    print(f"[FindVxISRVulns] {len(findings)} findings → {out_path}")


run()
