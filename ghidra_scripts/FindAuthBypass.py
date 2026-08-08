# FindAuthBypass.py — Ghidra headless script
# Finds comparison functions that always return true, magic byte checks,
# and auth gate patterns.
#
# Usage: -postScript FindAuthBypass.py <output_dir>
# Output: <output_dir>/FindAuthBypass.json

import json
import os

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor


AUTH_FUNCTION_NAMES = [
    "auth", "authenticate", "check_auth", "verify", "login", "is_admin",
    "check_password", "validate", "authorized", "check_user", "check_login",
    "is_valid", "check_token", "verify_signature", "check_crc",
]

MAGIC_BYTES = [
    b"\xde\xad\xbe\xef", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce",
    b"\x41\x42\x43\x44",
]


def _looks_like_auth(fn_name):
    name_lower = fn_name.lower()
    return any(a in name_lower for a in AUTH_FUNCTION_NAMES)


def _decompile_fn(ifc, fn, mon):
    try:
        res = ifc.decompileFunction(fn, 20, mon)
        if res and res.decompileCompleted():
            dc = res.getDecompiledFunction()
            return dc.getC()[:2000] if dc else ""
    except Exception:
        pass
    return ""


def _always_returns_true(decomp_code):
    """Heuristic: function has 'return 1' or 'return true' without conditional path."""
    lines = decomp_code.splitlines()
    returns = [l for l in lines if "return" in l]
    if not returns:
        return False
    # All return paths return 1 / true
    trivial = all("return 1" in r or "return true" in r or "return 0x1" in r
                  for r in returns)
    return trivial and len(returns) <= 3


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_out"
    out_file = os.path.join(out_dir, "FindAuthBypass.json")

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
        if not _looks_like_auth(name):
            continue

        decomp = _decompile_fn(ifc, fn, mon)
        if not decomp:
            continue

        title = None
        evidence = ""

        if _always_returns_true(decomp):
            title = "Auth function always returns true: " + name
            evidence = "All return paths return 1/true — authentication gate bypassed"
        elif "strcmp" in decomp and ("== 0" in decomp or "!= 0" in decomp):
            title = "String comparison in auth function: " + name
            evidence = "strcmp-based authentication — timing attack or off-by-one possible"
        elif "memcmp" in decomp:
            title = "memcmp in auth function (timing attack): " + name
            evidence = "memcmp() is not constant-time — timing oracle possible"

        if title:
            findings.append({
                "title":    title,
                "cwe":      "CWE-287",
                "severity": "HIGH",
                "address":  str(fn.getEntryPoint()),
                "function": name,
                "evidence": evidence,
                "decompile": decomp,
            })

    try:
        with open(out_file, "w") as fh:
            json.dump({"findings": findings}, fh)
        println("FindAuthBypass: %d findings → %s" % (len(findings), out_file))
    except Exception as e:
        println("FindAuthBypass error: " + str(e))


run()
