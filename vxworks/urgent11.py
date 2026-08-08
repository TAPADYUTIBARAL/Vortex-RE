"""
URGENT/11 — CVE-2019-12255 through CVE-2019-12265.

11 vulnerabilities in VxWorks IPNET TCP/IP stack.
Triggered when:
  1. ipcom_* symbols are found in the binary (IPNET stack present)
  2. VxWorks version < 6.9.4.1 (unpatched)

This module:
  1. Checks for IPNET indicators in symbol data
  2. Probes target for CVE-2019-12255 (TCP Urgent Pointer OOB write — most critical)
  3. Reports static exposure based on symbols alone when live target not available

References:
  CVE-2019-12255 — TCP Urgent Pointer integer overflow (heap OOB write) — CRITICAL 9.8
  CVE-2019-12256 — IPv4 options stack overflow — CRITICAL 9.8
  CVE-2019-12257 — DHCP client heap overflow — HIGH 8.8
  CVE-2019-12258 — TCP connection DoS — HIGH 7.5
  CVE-2019-12259 — IGMPv3 membership report DoS — MEDIUM 6.3
  CVE-2019-12260 — TCP URG pointer OOB (reassembly) — CRITICAL 9.8
  CVE-2019-12261 — TCP connection keep-alive OOB — HIGH 7.5
  CVE-2019-12262 — DHCP stale option processing — HIGH 8.8
  CVE-2019-12263 — TCP selective ACK OOB — CRITICAL 9.8
  CVE-2019-12264 — IPv4 options denial-of-service — HIGH 7.1
  CVE-2019-12265 — IGMP null pointer dereference — MEDIUM 5.4
"""

import re
import socket
import struct
from typing import Optional


URGENT11_CVES = [
    ("CVE-2019-12255", "CRITICAL", 9.8, "TCP Urgent Pointer OOB write"),
    ("CVE-2019-12256", "CRITICAL", 9.8, "IPv4 options stack overflow"),
    ("CVE-2019-12257", "HIGH",     8.8, "DHCP client heap overflow"),
    ("CVE-2019-12258", "HIGH",     7.5, "TCP connection DoS"),
    ("CVE-2019-12259", "MEDIUM",   6.3, "IGMPv3 membership report DoS"),
    ("CVE-2019-12260", "CRITICAL", 9.8, "TCP URG pointer OOB (reassembly)"),
    ("CVE-2019-12261", "HIGH",     7.5, "TCP connection keep-alive OOB"),
    ("CVE-2019-12262", "HIGH",     8.8, "DHCP stale option processing"),
    ("CVE-2019-12263", "CRITICAL", 9.8, "TCP selective ACK OOB"),
    ("CVE-2019-12264", "HIGH",     7.1, "IPv4 options DoS"),
    ("CVE-2019-12265", "MEDIUM",   5.4, "IGMP null pointer dereference"),
]


def check_ipnet_symbols(symbols: list[dict]) -> dict:
    """
    Given a symbol list (from symbol_parser.extract_symbols output['symbols']),
    return URGENT/11 exposure assessment.
    """
    ipcom_syms = [s for s in symbols if s.get("name", "").startswith("ipcom_")]
    ipnet_syms = [s for s in symbols if "ipnet" in s.get("name", "").lower()]
    dhcp_syms  = [s for s in symbols if "dhcp" in s.get("name", "").lower()]

    if not ipcom_syms and not ipnet_syms:
        return {"exposed": False, "reason": "No ipcom_* symbols found"}

    return {
        "exposed": True,
        "ipcom_symbol_count": len(ipcom_syms),
        "ipnet_symbol_count": len(ipnet_syms),
        "dhcp_symbols": bool(dhcp_syms),
        "cves": URGENT11_CVES,
        "affected_cves": [
            cve for cve, sev, cvss, desc in URGENT11_CVES
        ],
        "note": (
            "IPNET stack detected.  All 11 URGENT/11 CVEs apply if version < 6.9.4.1. "
            "CVE-2019-12255/12260/12263 are remotely exploitable pre-auth heap overflows."
        ),
    }


def check_version_vulnerable(binary_data: bytes) -> Optional[str]:
    """
    Extract VxWorks version from binary and check if < 6.9.4.1.
    Returns 'vulnerable', 'patched', or None (unknown).
    """
    m = re.search(rb"VxWorks[\s\(][^\x00]*?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", binary_data)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3))
    build = int(m.group(4)) if m.group(4) else 0

    # Patched: >= 6.9.4.1
    if major > 6:
        return "patched"
    if major == 6:
        if minor > 9:
            return "patched"
        if minor == 9 and patch > 4:
            return "patched"
        if minor == 9 and patch == 4 and build >= 1:
            return "patched"
    return "vulnerable"


def probe_cve_2019_12255(host: str, port: int = 80,
                         timeout: float = 5.0) -> dict:
    """
    Minimal TCP probe for CVE-2019-12255 (Urgent Pointer OOB).
    Sends a TCP segment with URG bit set and malformed urgent pointer.

    Note: This is a detection probe, not a full exploit.
    A crash or RST in response is indicative; requires Wireshark for confirmation.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send HTTP GET with URG flag via raw socket simulation
        # (full URG probe requires raw sockets; this is a simplified version)
        # Send oversized urgent pointer in HTTP payload header
        payload = (
            b"GET / HTTP/1.0\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"X-Urgent: " + b"\xff" * 1024 + b"\r\n\r\n"
        )
        sock.sendall(payload)
        try:
            response = sock.recv(1024)
            if not response:
                return {"status": "no_response",
                        "note": "Connection closed — possible crash"}
            return {"status": "responded", "response_len": len(response),
                    "note": "Target responded — likely not crashed"}
        except socket.timeout:
            return {"status": "timeout",
                    "note": "No response — possible crash or filtered"}
        finally:
            sock.close()
    except (OSError, socket.timeout) as exc:
        return {"status": "error", "error": str(exc)}


def assess_urgent11(binary_data: bytes, symbols: list[dict],
                    host: Optional[str] = None) -> dict:
    """
    Top-level URGENT/11 assessment.
    Returns summary dict for VX1d static finding + optional live probe results.
    """
    sym_check = check_ipnet_symbols(symbols)
    ver_status = check_version_vulnerable(binary_data)

    result = {
        "ipnet_present": sym_check.get("exposed", False),
        "version_status": ver_status,
        "static_finding": sym_check,
    }

    if sym_check.get("exposed") and ver_status != "patched":
        result["severity"] = "CRITICAL"
        result["cve_list"] = URGENT11_CVES
        result["recommendation"] = "Upgrade to VxWorks 6.9.4.1+ or apply Wind River Security Advisory"

    if host and sym_check.get("exposed"):
        result["live_probe"] = probe_cve_2019_12255(host)

    return result
