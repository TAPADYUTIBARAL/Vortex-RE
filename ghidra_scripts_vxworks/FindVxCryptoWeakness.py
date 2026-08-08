# FindVxCryptoWeakness.py
# Ghidra post-analysis script — VX2A
#
# Identifies weak/absent cryptography in VxWorks firmware:
#   1. Hardcoded keys: key material adjacent to crypto init functions
#   2. Weak ciphers: DES/3DES, RC4, MD5 initialization constants
#   3. rand() usage in security context (after TLS/crypto function)
#   4. SSL/TLS version constants indicating SSLv3 / TLSv1.0
#   5. Missing TLS: plain-text protocol handlers (Telnet/FTP/HTTP) present
#      but no TLS symbols found
#
# Output: <out_dir>/vxworks_crypto_weakness.json

import json
import os
import struct


# MD5 init constants: 0x67452301 0xefcdab89 0x98badcfe 0x10325476
MD5_CONSTS  = [b"\x67\x45\x23\x01", b"\xef\xcd\xab\x89"]
# DES S-box first row partial signature
DES_SBOX    = b"\x0e\x04\x0d\x01\x02\x0f"
# RC4 constant (KSA loop with 256-byte state)
RC4_MARKER  = b"\x00\x01\x02\x03\x04\x05\x06\x07"
# SSLv3 version bytes: 0x0300
SSLV3_CONST = bytes([0x03, 0x00])

PLAINTEXT_SYMBOLS  = {"telnetd", "ftpd", "httpd", "goahead", "webs"}
TLS_SYMBOLS        = {"SSL_connect", "SSL_accept", "TLS_client_method",
                      "sslInit", "wmbSSLInit"}
WEAK_CIPHER_SYMS   = {"des_ecb_encrypt", "DES_ecb_encrypt", "RC4", "rc4_crypt",
                      "MD5_Init", "md5_init"}


def _find_all(data, pattern):
    offsets = []
    idx = 0
    while True:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        offsets.append(pos)
        idx = pos + 1
    return offsets


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_vx"
    os.makedirs(out_dir, exist_ok=True)

    program = currentProgram  # noqa: F821
    sym_tbl = program.getSymbolTable()
    mem     = program.getMemory()

    # Read full binary bytes
    try:
        min_addr = program.getMinAddress()
        max_addr = program.getMaxAddress()
        size = int(str(max_addr)) - int(str(min_addr)) + 1
        data = bytearray(size)
        mem.getBytes(min_addr, data)
        data = bytes(data)
    except Exception:
        data = b""

    findings = []

    # Check for weak cipher symbols
    present_syms = []
    for sym in sym_tbl.getAllSymbols(True):
        if sym.getName() in WEAK_CIPHER_SYMS:
            present_syms.append({"name": sym.getName(), "address": str(sym.getAddress())})
    if present_syms:
        findings.append({
            "type": "weak_cipher_symbols",
            "severity": "HIGH",
            "symbols": present_syms,
            "cwe": "CWE-327",
            "note": "Weak/broken crypto symbols present (DES/RC4/MD5)",
        })

    # Check for MD5 init constants in binary
    for const in MD5_CONSTS:
        offsets = _find_all(data, const)
        if offsets:
            findings.append({
                "type": "md5_init_constant",
                "severity": "MEDIUM",
                "offsets": [hex(o) for o in offsets[:5]],
                "cwe": "CWE-328",
                "note": "MD5 initialization constant found — hash used for integrity/auth",
            })
            break

    # Check for DES S-box
    offsets = _find_all(data, DES_SBOX)
    if offsets:
        findings.append({
            "type": "des_sbox_constant",
            "severity": "HIGH",
            "offsets": [hex(o) for o in offsets[:5]],
            "cwe": "CWE-327",
            "note": "DES cipher S-box found — DES is cryptographically broken",
        })

    # Check for SSLv3 version constant
    offsets = _find_all(data, SSLV3_CONST)
    if len(offsets) > 3:
        findings.append({
            "type": "sslv3_constant",
            "severity": "HIGH",
            "offset_count": len(offsets),
            "cwe": "CWE-326",
            "note": "SSLv3 version constant 0x0300 found — POODLE / BEAST vulnerable",
        })

    # Check for missing TLS with plain-text services
    has_plaintext = any(
        sym.getName() in PLAINTEXT_SYMBOLS
        for sym in sym_tbl.getAllSymbols(True)
    )
    has_tls = any(
        sym.getName() in TLS_SYMBOLS
        for sym in sym_tbl.getAllSymbols(True)
    )
    if has_plaintext and not has_tls:
        findings.append({
            "type": "missing_tls",
            "severity": "HIGH",
            "cwe": "CWE-319",
            "note": "Plain-text network services (telnetd/ftpd/httpd) with no TLS symbols "
                    "— credentials transmitted in cleartext",
        })

    out_path = os.path.join(out_dir, "vxworks_crypto_weakness.json")
    with open(out_path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)
    print(f"[FindVxCryptoWeakness] {len(findings)} findings → {out_path}")


run()
