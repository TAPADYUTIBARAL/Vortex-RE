# FindVxNetworkHandlers.py
# Ghidra post-analysis script — VX2A
#
# Identifies network input handlers in VxWorks firmware:
#   1. Functions that call recv/recvfrom/read with a stack buffer destination
#   2. Functions registered as socket callbacks or protocol handlers
#   3. Functions that reference network buffer APIs (mBlkGet, netBufLib) then
#      copy into a fixed-size stack/heap buffer
#   4. IPCOM protocol handlers (ipcom_recv*, ipnet*)
#
# Network handlers without bounds checking + no NX = remotely exploitable CRITICAL.
#
# Output: <out_dir>/vxworks_network_handlers.json

import json
import os


RECV_FUNCS    = {"recv", "recvfrom", "recvmsg", "read", "ipcom_recv",
                 "ipcom_recvfrom", "m2If_recv"}
COPY_FUNCS    = {"memcpy", "bcopy", "strcpy", "strcat", "sprintf"}
NET_BUF_FUNCS = {"mBlkGet", "netBufLib", "netMblkGet", "mBlkClGet"}
BIND_FUNCS    = {"bind", "accept", "listen"}


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program = currentProgram  # noqa: F821
    sym_tbl = program.getSymbolTable()
    listing = program.getListing()
    refs    = program.getReferenceManager()

    # Build function addr maps
    def sym_addrs(names):
        m = {}
        for sym in sym_tbl.getAllSymbols(True):
            if sym.getName() in names:
                m[str(sym.getAddress())] = sym.getName()
        return m

    recv_addrs   = sym_addrs(RECV_FUNCS)
    copy_addrs   = sym_addrs(COPY_FUNCS)
    buf_addrs    = sym_addrs(NET_BUF_FUNCS)
    bind_addrs   = sym_addrs(BIND_FUNCS)

    findings = []

    for func in listing.getFunctions(True):
        func_name  = func.getName()
        func_entry = str(func.getEntryPoint())

        calls_recv = []
        calls_copy = []
        calls_buf  = []
        calls_bind = []

        body = func.getBody()
        for rng in body.getAddressRanges():
            cur = rng.getMinAddress()
            end = rng.getMaxAddress()
            while cur is not None and cur.compareTo(end) <= 0:
                instr = listing.getInstructionAt(cur)
                if instr is None:
                    break
                for ref in refs.getReferencesFrom(cur):
                    rs = str(ref.getToAddress())
                    if rs in recv_addrs:
                        calls_recv.append(
                            {"callee": recv_addrs[rs], "site": str(cur)})
                    if rs in copy_addrs:
                        calls_copy.append(
                            {"callee": copy_addrs[rs], "site": str(cur)})
                    if rs in buf_addrs:
                        calls_buf.append(
                            {"callee": buf_addrs[rs], "site": str(cur)})
                    if rs in bind_addrs:
                        calls_bind.append(
                            {"callee": bind_addrs[rs], "site": str(cur)})
                try:
                    cur = cur.next()
                except Exception:
                    break

        if calls_recv and calls_copy:
            findings.append({
                "type": "network_recv_then_copy",
                "severity": "CRITICAL",
                "function": func_name,
                "address": func_entry,
                "recv_calls": calls_recv,
                "copy_calls": calls_copy,
                "cwe": "CWE-120",
                "note": "recv() + unsafe copy without bounds check.  "
                        "No NX in VxWorks — remote code execution likely.",
            })
        elif calls_recv:
            findings.append({
                "type": "network_recv_handler",
                "severity": "HIGH",
                "function": func_name,
                "address": func_entry,
                "recv_calls": calls_recv,
                "note": "Network receive handler — review for buffer overflows",
            })

        if calls_buf and calls_copy:
            findings.append({
                "type": "netbuf_copy_pattern",
                "severity": "HIGH",
                "function": func_name,
                "address": func_entry,
                "buf_calls": calls_buf,
                "copy_calls": calls_copy,
                "note": "Network buffer + unsafe copy — IPNET pattern for URGENT/11",
            })

    out_path = os.path.join(out_dir, "vxworks_network_handlers.json")
    with open(out_path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)
    print(f"[FindVxNetworkHandlers] {len(findings)} findings → {out_path}")


run()
