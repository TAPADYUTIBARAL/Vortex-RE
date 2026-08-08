# FindCryptoPatterns.py — Ghidra headless script
# Finds hardcoded AES keys, weak PRNG calls, ECB mode constants.
#
# Usage: -postScript FindCryptoPatterns.py <output_dir>
# Output: <output_dir>/FindCryptoPatterns.json

import json
import os

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor


# AES S-box first 16 bytes — presence indicates AES constant table
AES_SBOX_MAGIC = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]

WEAK_CRYPTO_FNS = [
    ("rand",     "CWE-330", "Weak PRNG: rand() — predictable output", "MEDIUM"),
    ("srand",    "CWE-330", "Weak PRNG seeding: srand()", "LOW"),
    ("MD5",      "CWE-327", "Weak hash: MD5", "HIGH"),
    ("MD5_Init", "CWE-327", "Weak hash: MD5", "HIGH"),
    ("SHA1",     "CWE-327", "Weak hash: SHA-1", "MEDIUM"),
    ("DES_",     "CWE-327", "Weak cipher: DES", "HIGH"),
    ("ECB",      "CWE-327", "Weak cipher mode: ECB (no diffusion)", "HIGH"),
    ("AES_ECB",  "CWE-327", "AES-ECB mode — no semantic security", "HIGH"),
    ("RC4",      "CWE-327", "Weak cipher: RC4", "HIGH"),
    ("EVP_EncryptInit", "CWE-326", "OpenSSL EVP init — verify mode/key", "MEDIUM"),
]


def _search_aes_sbox(program):
    """Search for AES S-box magic bytes in data sections."""
    memory = program.getMemory()
    magic = bytes(AES_SBOX_MAGIC)
    results = []
    blocks = list(memory.getBlocks())
    for block in blocks:
        if not block.isInitialized():
            continue
        try:
            size = block.getSize()
            data = bytearray(size)
            block.getBytes(block.getStart(), data, 0, size)
            idx = data.find(magic)
            if idx >= 0:
                addr = block.getStart().add(idx)
                results.append({
                    "title":    "AES S-box constant table found (hardcoded AES key nearby?)",
                    "cwe":      "CWE-321",
                    "severity": "HIGH",
                    "address":  str(addr),
                    "function": "?",
                    "evidence": "AES S-box magic at " + str(addr),
                    "decompile": "",
                })
        except Exception:
            pass
    return results


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_out"
    out_file = os.path.join(out_dir, "FindCryptoPatterns.json")

    program = currentProgram
    sym_table = program.getSymbolTable()
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(program)
    mon = ConsoleTaskMonitor()
    fm  = program.getFunctionManager()

    findings = []

    # Search for weak crypto function calls
    for fn_name, cwe, title, sev in WEAK_CRYPTO_FNS:
        syms = list(sym_table.getSymbols(fn_name))
        for sym in syms:
            refs = list(sym.getReferences())
            for ref in refs:
                call_addr = ref.getFromAddress()
                caller_fn = fm.getFunctionContaining(call_addr)
                if not caller_fn:
                    continue
                decomp_code = ""
                try:
                    res = ifc.decompileFunction(caller_fn, 15, mon)
                    if res and res.decompileCompleted():
                        dc = res.getDecompiledFunction()
                        decomp_code = dc.getC()[:1500] if dc else ""
                except Exception:
                    pass
                findings.append({
                    "title":    title + " in " + caller_fn.getName(),
                    "cwe":      cwe,
                    "severity": sev,
                    "address":  str(call_addr),
                    "function": caller_fn.getName(),
                    "evidence": "%s() call in %s at %s" % (fn_name, caller_fn.getName(), str(call_addr)),
                    "decompile": decomp_code,
                })

    # Search for AES S-box
    findings.extend(_search_aes_sbox(program))

    try:
        with open(out_file, "w") as fh:
            json.dump({"findings": findings}, fh)
        println("FindCryptoPatterns: %d findings → %s" % (len(findings), out_file))
    except Exception as e:
        println("FindCryptoPatterns error: " + str(e))


run()
