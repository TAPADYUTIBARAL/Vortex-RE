# FindUpdateHandlers.py — Ghidra headless script
# Finds functions that accept large buffers from network/UART — primary attack surface
# for firmware update, config push, and remote management handlers.
#
# Usage: -postScript FindUpdateHandlers.py <output_dir>
# Output: <output_dir>/FindUpdateHandlers.json

import json
import os

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


UPDATE_NAME_HINTS = [
    "update", "firmware", "upgrade", "ota", "fota", "download", "receive",
    "parse", "handler", "process", "handle", "dispatch", "request",
    "upload", "write_flash", "flash_write", "nvs_write", "eeprom",
]

INPUT_SOURCES = [
    "recv", "recvfrom", "read", "fread", "uart", "usart", "spi_read",
    "i2c_read", "can_read", "net_read", "socket", "accept",
]

LARGE_BUFFER_THRESHOLD = 256  # bytes


def _name_suggests_handler(fn_name):
    n = fn_name.lower()
    return any(h in n for h in UPDATE_NAME_HINTS)


def _has_large_alloca_or_array(decomp_code):
    """Heuristic: look for large local buffer allocations."""
    import re
    # char buf[N] where N >= 256
    m = re.search(r"(?:char|uint8|byte)\s+\w+\[(\d+)\]", decomp_code)
    if m and int(m.group(1)) >= LARGE_BUFFER_THRESHOLD:
        return int(m.group(1))
    # alloca(N)
    m2 = re.search(r"alloca\s*\(\s*(\d+)\s*\)", decomp_code)
    if m2 and int(m2.group(1)) >= LARGE_BUFFER_THRESHOLD:
        return int(m2.group(1))
    return 0


def _has_input_source(decomp_code):
    code_lower = decomp_code.lower()
    return any(src in code_lower for src in INPUT_SOURCES)


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_out"
    out_file = os.path.join(out_dir, "FindUpdateHandlers.json")

    program = currentProgram
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(program)
    mon = ConsoleTaskMonitor()
    fm  = program.getFunctionManager()

    findings = []
    funcs = list(fm.getFunctions(True))

    for fn in funcs:
        if monitor.isCancelled():
            break
        name = fn.getName()
        is_handler = _name_suggests_handler(name)

        decomp = ""
        try:
            res = ifc.decompileFunction(fn, 20, mon)
            if res and res.decompileCompleted():
                dc = res.getDecompiledFunction()
                decomp = dc.getC()[:2500] if dc else ""
        except Exception:
            pass

        if not decomp:
            continue

        buf_size = _has_large_alloca_or_array(decomp)
        has_input = _has_input_source(decomp)

        if not (is_handler or (buf_size > 0 and has_input)):
            continue

        evidence_parts = []
        if is_handler:
            evidence_parts.append("Name suggests update/handler function")
        if buf_size:
            evidence_parts.append("Large local buffer: %d bytes" % buf_size)
        if has_input:
            evidence_parts.append("Network/UART input source detected")

        findings.append({
            "title":    "Update/handler with large external input: " + name,
            "cwe":      "CWE-20",
            "severity": "HIGH",
            "address":  str(fn.getEntryPoint()),
            "function": name,
            "evidence": "; ".join(evidence_parts),
            "decompile": decomp,
        })

    try:
        with open(out_file, "w") as fh:
            json.dump({"findings": findings}, fh)
        println("FindUpdateHandlers: %d findings → %s" % (len(findings), out_file))
    except Exception as e:
        println("FindUpdateHandlers error: " + str(e))


run()
