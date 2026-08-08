# FindVxWDBExposure.py
# Ghidra post-analysis script — VX2A
#
# Detects WDB (Wind Debug Bridge) initialization and exposure:
#   1. Presence of wdbTgtSvr / wdbSvcAdd / wdbInit symbols
#   2. WDB service task name "tWdbTask" in strings
#   3. UDP socket bind call with port 17185 (0x4321)
#   4. wdbCommDevInit / wdbUdpInit calls
#
# WDB open = unauthenticated full memory R/W = CRITICAL.
#
# Output: <out_dir>/vxworks_wdb_exposure.json

import json
import os


WDB_PORT_HEX = 0x4321   # 17185
WDB_SYMBOLS  = {"wdbTgtSvr", "wdbSvcAdd", "wdbInit", "wdbCommDevInit",
                "wdbUdpInit", "wdbEndPktDevInit", "wdbNetIpProtoInit"}
WDB_STRINGS  = [b"tWdbTask", b"wdbTask", b"WDB Target Server"]


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program = currentProgram  # noqa: F821
    sym_tbl = program.getSymbolTable()
    listing = program.getListing()
    mem     = program.getMemory()

    findings = []

    # Check for WDB symbols
    found_syms = []
    for sym in sym_tbl.getAllSymbols(True):
        name = sym.getName()
        if name in WDB_SYMBOLS:
            found_syms.append({"symbol": name, "address": str(sym.getAddress())})

    if found_syms:
        findings.append({
            "type": "wdb_symbols_present",
            "severity": "CRITICAL",
            "symbols": found_syms,
            "cwe": "CWE-288",
            "note": "WDB symbols present — service likely enabled.  "
                    "UDP/17185 provides unauthenticated memory R/W.",
            "cve": "N/A (design vulnerability)",
        })

    # Check for WDB string markers in binary
    for pat in WDB_STRINGS:
        addr = mem.findBytes(program.getMinAddress(), pat, None, True, None)
        if addr is not None:
            findings.append({
                "type": "wdb_string_marker",
                "severity": "HIGH",
                "string": pat.decode(errors="replace"),
                "address": str(addr),
                "note": "WDB task string found — indicates WDB is active",
            })

    # Check for port 17185 constant in code
    for block in mem.getBlocks():
        if not block.isExecute():
            continue
        start = block.getStart()
        end   = block.getEnd()
        try:
            data = bytearray(block.getSize())
            mem.getBytes(start, data)
            # Look for 0x4321 (big-endian) or 0x2143 (little-endian)
            port_be = bytes([0x00, 0x00, 0x43, 0x21])
            port_le = bytes([0x21, 0x43, 0x00, 0x00])
            for pattern, endian in [(port_be, "big"), (port_le, "little")]:
                idx = 0
                while True:
                    pos = bytes(data).find(pattern, idx)
                    if pos == -1:
                        break
                    findings.append({
                        "type": "wdb_port_constant",
                        "severity": "MEDIUM",
                        "address": str(start.add(pos)),
                        "value": "17185 (WDB UDP port)",
                        "endian": endian,
                        "note": "Port 17185 constant — likely WDB socket bind",
                    })
                    idx = pos + 1
        except Exception:
            pass

    out_path = os.path.join(out_dir, "vxworks_wdb_exposure.json")
    with open(out_path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)
    print(f"[FindVxWDBExposure] {len(findings)} findings → {out_path}")


run()
