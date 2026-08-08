"""
VxWorks fuzz runner — Stage VX3e.

Target protocols commonly exposed in VxWorks firmware:
  - FTP (port 21)   — ftpd
  - Telnet (port 23) — shell
  - HTTP (port 80)  — webserver (goahead, wind web server)
  - SNMP (port 161) — snmpd
  - WDB (port 17185) — wind debug bridge
  - Custom TCP services discovered from symbol analysis

Uses boofuzz with VxWorks-specific mutation strategies.
Falls back to radamsa if boofuzz unavailable.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Optional


def _run(cmd: list, timeout: int = 60) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).decode(errors="replace")
    except Exception as exc:
        return False, str(exc)


def _boofuzz_available() -> bool:
    try:
        import boofuzz  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


def fuzz_http_vxworks(host: str, port: int = 80,
                      out_dir: str = "fuzz_results",
                      max_cases: int = 5000) -> dict:
    """
    HTTP fuzzer targeting Wind Web Server / GoAhead patterns.
    VxWorks HTTP servers often have buffer overflows in request parsing.
    """
    if not _boofuzz_available():
        return _radamsa_fallback_http(host, port, out_dir)

    try:
        from boofuzz import Session, Target, TCPSocketConnection  # type: ignore
        from boofuzz import s_initialize, s_string, s_delim, s_static  # type: ignore
        from boofuzz import s_get, s_block_start, s_block_end  # type: ignore

        os.makedirs(out_dir, exist_ok=True)
        db_path = os.path.join(out_dir, "http_fuzz.db")

        target = Target(connection=TCPSocketConnection(host, port, timeout=5.0))
        session = Session(
            target=target,
            sleep_time=0.01,
            db_filename=db_path,
        )

        s_initialize("HTTP GET")
        s_string("GET", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("/", fuzzable=True)
        s_delim(" ", fuzzable=False)
        s_string("HTTP/1.0", fuzzable=False)
        s_static(b"\r\n")
        s_string("Host", fuzzable=False)
        s_static(b": ")
        s_string(host, fuzzable=True)
        s_static(b"\r\n")
        s_string("User-Agent", fuzzable=False)
        s_static(b": ")
        s_string("Mozilla/5.0", fuzzable=True)
        s_static(b"\r\n\r\n")

        session.connect(s_get("HTTP GET"))
        session.fuzz(max_depth=max_cases)

        return {
            "status": "ok",
            "protocol": "http",
            "host": host, "port": port,
            "test_cases": session.num_mutations,
            "db": db_path,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def fuzz_ftp_vxworks(host: str, port: int = 21,
                     out_dir: str = "fuzz_results",
                     max_cases: int = 3000) -> dict:
    """FTP fuzzer for VxWorks ftpd — commonly vulnerable to CWD/MKD overflows."""
    if not _boofuzz_available():
        return {"status": "tool_missing", "tool": "boofuzz",
                "install": "pip install boofuzz"}

    try:
        from boofuzz import Session, Target, TCPSocketConnection  # type: ignore
        from boofuzz import s_initialize, s_string, s_static, s_get  # type: ignore

        os.makedirs(out_dir, exist_ok=True)
        db_path = os.path.join(out_dir, "ftp_fuzz.db")

        target = Target(connection=TCPSocketConnection(host, port, timeout=5.0))
        session = Session(target=target, sleep_time=0.01, db_filename=db_path)

        # USER command fuzzing
        s_initialize("FTP USER")
        s_static(b"USER ")
        s_string("anonymous", fuzzable=True)
        s_static(b"\r\n")
        session.connect(s_get("FTP USER"))

        # CWD command fuzzing (common overflow target)
        s_initialize("FTP CWD")
        s_static(b"CWD ")
        s_string("/", fuzzable=True)
        s_static(b"\r\n")
        session.connect(s_get("FTP CWD"))

        # MKD command
        s_initialize("FTP MKD")
        s_static(b"MKD ")
        s_string("dir", fuzzable=True)
        s_static(b"\r\n")
        session.connect(s_get("FTP MKD"))

        session.fuzz(max_depth=max_cases)

        return {
            "status": "ok",
            "protocol": "ftp",
            "host": host, "port": port,
            "db": db_path,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def fuzz_tcp_generic(host: str, port: int,
                     out_dir: str = "fuzz_results",
                     max_cases: int = 2000) -> dict:
    """Generic TCP fuzzer for custom VxWorks services."""
    if not _boofuzz_available():
        return _radamsa_fallback_tcp(host, port, out_dir)

    try:
        from boofuzz import Session, Target, TCPSocketConnection  # type: ignore
        from boofuzz import s_initialize, s_string, s_static, s_get  # type: ignore

        os.makedirs(out_dir, exist_ok=True)
        db_path = os.path.join(out_dir, f"tcp_{port}_fuzz.db")

        target = Target(connection=TCPSocketConnection(host, port, timeout=5.0))
        session = Session(target=target, sleep_time=0.01, db_filename=db_path)

        s_initialize("raw_tcp")
        s_string("AAAA", fuzzable=True)
        s_static(b"\r\n")
        session.connect(s_get("raw_tcp"))
        session.fuzz(max_depth=max_cases)

        return {
            "status": "ok",
            "protocol": "tcp",
            "host": host, "port": port,
            "db": db_path,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _radamsa_fallback_http(host: str, port: int,
                            out_dir: str) -> dict:
    """Use radamsa to mutate HTTP requests when boofuzz is unavailable."""
    if not shutil.which("radamsa"):
        return {"status": "tool_missing",
                "tools": "boofuzz or radamsa",
                "install": "pip install boofuzz  OR  apt install radamsa"}

    os.makedirs(out_dir, exist_ok=True)
    seed = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
    seed_file = os.path.join(out_dir, "seed.txt")
    with open(seed_file, "w") as f:
        f.write(seed)

    crashes = 0
    for i in range(200):
        ok, mutated = _run(["radamsa", seed_file])
        if not mutated:
            continue
        try:
            sock = socket.create_connection((host, port), timeout=3.0)
            sock.sendall(mutated.encode(errors="replace"))
            try:
                sock.recv(1024)
            except socket.timeout:
                crashes += 1
            sock.close()
        except (OSError, socket.timeout):
            crashes += 1
        time.sleep(0.05)

    return {
        "status": "ok",
        "tool": "radamsa",
        "test_cases": 200,
        "possible_crashes": crashes,
        "note": "install boofuzz for structured fuzzing",
    }


def _radamsa_fallback_tcp(host: str, port: int,
                           out_dir: str) -> dict:
    """Radamsa TCP fallback."""
    if not shutil.which("radamsa"):
        return {"status": "tool_missing", "install": "apt install radamsa"}

    os.makedirs(out_dir, exist_ok=True)
    seed_file = os.path.join(out_dir, "tcp_seed.bin")
    with open(seed_file, "wb") as f:
        f.write(b"\x00" * 64)

    crashes = 0
    for _ in range(100):
        ok, mutated = _run(["radamsa", "--output", "-", seed_file])
        if not mutated:
            continue
        try:
            sock = socket.create_connection((host, port), timeout=2.0)
            sock.sendall(mutated.encode(errors="replace")[:4096])
            try:
                sock.recv(1024)
            except socket.timeout:
                crashes += 1
            sock.close()
        except (OSError, socket.timeout):
            crashes += 1

    return {"status": "ok", "tool": "radamsa", "test_cases": 100,
            "possible_crashes": crashes}


def fuzz_all_services(host: str, services: list[dict],
                      out_dir: str = "fuzz_results") -> list[dict]:
    """
    Fuzz all discovered VxWorks services.
    services: list of {port, protocol} dicts from VX1e attack surface analysis.
    """
    results = []
    for svc in services:
        port = svc.get("port", 80)
        proto = svc.get("protocol", "tcp").lower()

        if proto == "http" or port in (80, 443, 8080, 8443):
            r = fuzz_http_vxworks(host, port, out_dir)
        elif proto == "ftp" or port == 21:
            r = fuzz_ftp_vxworks(host, port, out_dir)
        else:
            r = fuzz_tcp_generic(host, port, out_dir)

        r["service"] = svc
        results.append(r)

    return results
