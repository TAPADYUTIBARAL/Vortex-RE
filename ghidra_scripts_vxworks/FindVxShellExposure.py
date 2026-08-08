# FindVxShellExposure.py
# Ghidra post-analysis script — VX2A
#
# Detects VxWorks shell initialization and exposure:
#   1. shellInit / shellSpawn / shellMainLoop symbols
#   2. telnetd / rshd task initialization
#   3. Port 5001 / 23 constants in code
#   4. "tShell" task name string
#
# VxWorks shell on TCP port 5001 = unauthenticated RCE via sp() command.
#
# Output: <out_dir>/vxworks_shell_exposure.json

import json
import os


SHELL_SYMBOLS  = {"shellInit", "shellSpawn", "shellMainLoop", "shellLogin",
                  "remCurIdGet", "rlogind", "rshd", "telnetd", "telnetInit"}
SHELL_STRINGS  = [b"tShell", b"VxWorks Shell", b"->", b"rlogin", b"telnet"]
SHELL_PORTS_BE = [
    (bytes([0x00, 0x00, 0x13, 0x89]), "5001 (VxWorks shell)"),
    (bytes([0x00, 0x00, 0x00, 0x17]), "23 (Telnet)"),
]


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program = currentProgram  # noqa: F821
    sym_tbl = program.getSymbolTable()
    mem     = program.getMemory()

    findings = []

    found_syms = []
    for sym in sym_tbl.getAllSymbols(True):
        if sym.getName() in SHELL_SYMBOLS:
            found_syms.append({"symbol": sym.getName(), "address": str(sym.getAddress())})

    if found_syms:
        findings.append({
            "type": "shell_symbols_present",
            "severity": "CRITICAL",
            "symbols": found_syms,
            "cwe": "CWE-78",
            "note": "VxWorks shell symbols present.  TCP/5001 or Telnet/23 provides "
                    "unauthenticated command execution via sp() — arbitrary code exec.",
        })

    for pat in SHELL_STRINGS:
        addr = mem.findBytes(program.getMinAddress(), pat, None, True, None)
        if addr:
            findings.append({
                "type": "shell_string_marker",
                "severity": "HIGH",
                "string": pat.decode(errors="replace"),
                "address": str(addr),
            })

    for pattern, label in SHELL_PORTS_BE:
        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            try:
                data = bytearray(block.getSize())
                mem.getBytes(block.getStart(), data)
                idx = 0
                while True:
                    pos = bytes(data).find(pattern, idx)
                    if pos == -1:
                        break
                    findings.append({
                        "type": "shell_port_constant",
                        "severity": "MEDIUM",
                        "address": str(block.getStart().add(pos)),
                        "value": label,
                    })
                    idx = pos + 1
            except Exception:
                pass

    out_path = os.path.join(out_dir, "vxworks_shell_exposure.json")
    with open(out_path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)
    print(f"[FindVxShellExposure] {len(findings)} findings → {out_path}")


run()
