"""
Stage 3e — GDB cyclic offset confirmation.

Runs gdbserver + gdb-multiarch to measure exact offset to saved return address.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Optional

from models import Finding


def _run(cmd: list, input_text: str = None, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            cmd,
            input=input_text.encode() if input_text else None,
            capture_output=True,
            timeout=timeout,
        )
        return (r.stdout + r.stderr).decode(errors="replace")
    except Exception as exc:
        return f"[error: {exc}]"


def run_gdb_cyclic(path: str, finding: Finding, triage, timeout: int = 60,
                   priority_addrs: list = None) -> str:
    """
    Launch binary under gdbserver, connect gdb-multiarch, feed cyclic pattern,
    extract PC on crash to measure exact offset.

    priority_addrs: list of hex address strings from RankExploitTargets to set breakpoints.
    Returns a string summary of the GDB result (appended to emulation_trace).
    """
    if not shutil.which("gdbserver") or not shutil.which("gdb-multiarch"):
        return ""

    arch = triage.arch
    port = 12345

    # Generate cyclic pattern
    try:
        from pwn import cyclic  # type: ignore
        payload = cyclic(512)
    except ImportError:
        payload = b"A" * 512

    payload_file = tempfile.mktemp(suffix=".bin")
    with open(payload_file, "wb") as fh:
        fh.write(payload)

    try:
        # Start gdbserver
        gdbserver_cmd = ["gdbserver", f"127.0.0.1:{port}", path]
        if triage.extracted_path:
            env = dict(os.environ)
        else:
            env = os.environ

        gdbserver = subprocess.Popen(
            gdbserver_cmd,
            stdin=open(payload_file, "rb"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        time.sleep(1)

        if gdbserver.poll() is not None:
            return ""

        # Build breakpoints from Ghidra priority queue addresses (Gap 9)
        break_cmds = ""
        if priority_addrs:
            for addr in priority_addrs[:5]:
                break_cmds += f"break *{addr}\n"

        # Build GDB commands
        gdb_script = f"""
set architecture {_gdb_arch(arch)}
target remote 127.0.0.1:{port}
{break_cmds}continue
info registers
backtrace
quit
"""
        gdb_out = _run(
            ["gdb-multiarch", "--batch", "--command=/dev/stdin", path],
            input_text=gdb_script,
            timeout=timeout,
        )

        # Extract PC
        pc_match = re.search(r"\bpc\b\s+(0x[0-9a-fA-F]+)", gdb_out, re.IGNORECASE)
        if not pc_match:
            pc_match = re.search(r"\beip\b\s+(0x[0-9a-fA-F]+)", gdb_out, re.IGNORECASE)

        if pc_match:
            pc_val = pc_match.group(1)
            try:
                pc_bytes = bytes.fromhex(pc_val[2:].zfill(8))[:4]
                from pwn import cyclic_find  # type: ignore
                offset = cyclic_find(pc_bytes)
                if offset >= 0:
                    return f"GDB cyclic: PC={pc_val}  offset={offset}"
                return f"GDB crash: PC={pc_val}  (cyclic offset undetermined)"
            except Exception:
                return f"GDB crash: PC={pc_val}"

        return ""

    finally:
        try:
            gdbserver.kill()
            gdbserver.wait(timeout=3)
        except Exception:
            pass
        try:
            os.unlink(payload_file)
        except Exception:
            pass


def _gdb_arch(arch: str) -> str:
    mapping = {
        "arm":    "arm",
        "arm64":  "aarch64",
        "mips":   "mips",
        "x86":    "i386",
        "x86_64": "i386:x86-64",
        "riscv":  "riscv:rv32",
    }
    return mapping.get(arch, "arm")
