"""
Stage 4d — Fuzzing pass for unattempted attack surface.

Uses boofuzz for live service mutation fuzzing and radamsa for
file-format fuzzing of parsers. Any crash is immediately fed back
into the Stage 3 pipeline for primitive extraction.
"""

import os
import re
import shutil
import subprocess
import tempfile
from typing import List

from models import Finding


def run_fuzzer(unverified: List[Finding], triage, poc_dir: str) -> List[Finding]:
    """
    Run fuzzing on attack surface that had no Ghidra candidates.
    Returns list of Findings from crashes discovered during fuzzing.
    """
    findings = []

    # boofuzz: network service fuzzing
    if shutil.which("boofuzz") or _boofuzz_available():
        net_findings = _run_boofuzz(unverified, triage)
        findings.extend(net_findings)

    # radamsa: file-format fuzzing
    if shutil.which("radamsa"):
        file_findings = _run_radamsa(unverified, triage, poc_dir)
        findings.extend(file_findings)
    else:
        _note_missing("radamsa", "file-format mutation fuzzing skipped")

    return findings


def _boofuzz_available() -> bool:
    try:
        import boofuzz  # noqa: F401
        return True
    except ImportError:
        return False


def _note_missing(tool: str, msg: str) -> None:
    print(f"[~] [TOOL_MISSING] {tool} — {msg}")


def _run_boofuzz(unverified: List[Finding], triage) -> List[Finding]:
    """Generate and run a boofuzz session against network-facing candidates."""
    findings = []

    net_candidates = [
        f for f in unverified
        if any(k in f.title.lower() for k in ["network", "http", "tcp", "service",
                                                "update", "handler", "recv"])
    ]
    if not net_candidates:
        return []

    print(f"[*] boofuzz: fuzzing {len(net_candidates)} network candidate(s)...")

    # Write a boofuzz session script
    session_script = _build_boofuzz_script(net_candidates, triage)
    if not session_script:
        return []

    script_path = tempfile.mktemp(suffix="_boofuzz.py")
    try:
        with open(script_path, "w") as fh:
            fh.write(session_script)

        out, rc = _run(["python3", script_path], timeout=120)

        # Parse crash output
        if "crash" in out.lower() or "EXCEPTION" in out:
            findings.append(Finding(
                id="",
                stage="emulation",
                title="boofuzz crash detected in network service",
                cwe="CWE-400",
                severity="HIGH",
                component="network:fuzzing",
                evidence=out[:1000],
                confirmation="PLAUSIBLE",
                runtime_flag="NETWORK_STACK_DIFF",
                runtime_test_hint="Reproduce boofuzz crash on real device with network access",
                manual_steps=[
                    f"Run boofuzz session: python3 {os.path.basename(script_path)}",
                    "Monitor target for crash/restart",
                    "Capture crashing input with boofuzz --save-crashes",
                ],
            ))

    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    return findings


def _build_boofuzz_script(candidates: List[Finding], triage) -> str:
    return """#!/usr/bin/env python3
# [re_agent] Auto-generated boofuzz session
# Fuzzes common network service patterns

from boofuzz import *
import sys

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 80  # FIXME: adjust for target service port

def main():
    session = Session(
        target=Target(
            connection=TCPSocketConnection(TARGET_HOST, TARGET_PORT),
        ),
        sleep_time=0.1,
        crash_threshold_request=5,
    )

    # HTTP mutation fuzzing
    s_initialize("http_request")
    s_static(b"POST ")
    s_string("/", name="uri")
    s_static(b" HTTP/1.0\\r\\n")
    s_static(b"Host: ")
    s_string("localhost", name="host")
    s_static(b"\\r\\nContent-Length: ")
    s_size("body", output_format="ascii")
    s_static(b"\\r\\n\\r\\n")
    with s_block("body"):
        s_string("data=", name="param")
        s_string("AAAA", name="value")

    session.connect(s_get("http_request"))

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[boofuzz] Exception: {e}")

if __name__ == "__main__":
    main()
"""


def _run_radamsa(unverified: List[Finding], triage, poc_dir: str) -> List[Finding]:
    """Run radamsa file-format fuzzing against the target binary."""
    findings = []
    path = triage.binary_info.path
    arch = triage.arch
    qemu = {"arm": "qemu-arm", "arm64": "qemu-aarch64", "mips": "qemu-mips",
            "x86": "qemu-i386", "x86_64": "qemu-x86_64"}.get(arch, "qemu-arm")

    if not shutil.which(qemu):
        return []

    print(f"[*] radamsa: file-format fuzzing with {qemu}...")

    # Generate 20 mutated inputs from the first 4KB of the binary
    with open(path, "rb") as fh:
        sample = fh.read(4096)

    sample_file = tempfile.mktemp(suffix=".bin")
    with open(sample_file, "wb") as fh:
        fh.write(sample)

    crashes = []
    try:
        for i in range(20):
            mutated = tempfile.mktemp(suffix=f"_radamsa_{i}.bin")
            try:
                # Generate one mutation
                r = subprocess.run(
                    ["radamsa", "-o", mutated, sample_file],
                    capture_output=True, timeout=5,
                )
                if not os.path.exists(mutated):
                    continue

                # Run target with mutated input
                sysroot_args = ["-L", triage.extracted_path] if triage.extracted_path else []
                run_r = subprocess.run(
                    [qemu] + sysroot_args + [path],
                    stdin=open(mutated, "rb"),
                    capture_output=True,
                    timeout=10,
                )
                out = (run_r.stdout + run_r.stderr).decode(errors="replace")
                rc = run_r.returncode

                is_crash = rc in (-11, -6, -4, 139, 134) or any(
                    s in out for s in ["Segmentation fault", "SIGSEGV", "SIGBUS", "SIGABRT"]
                )
                if is_crash:
                    crashes.append((i, mutated, out, rc))
                    print(f"[+] radamsa crash #{i}: rc={rc}")
                    if len(crashes) >= 3:
                        break

            except Exception:
                pass
            finally:
                try:
                    if mutated != sample_file and os.path.exists(mutated):
                        # Keep first crash input for PoC
                        if not crashes or mutated != crashes[0][1]:
                            os.unlink(mutated)
                except Exception:
                    pass

    finally:
        try:
            os.unlink(sample_file)
        except Exception:
            pass

    for i, crash_input, crash_out, rc in crashes[:3]:
        crash_path = os.path.join(poc_dir, f"radamsa_crash_{i}.bin")
        try:
            if os.path.exists(crash_input):
                import shutil as _sh
                _sh.copy(crash_input, crash_path)
                os.unlink(crash_input)
        except Exception:
            crash_path = "?"

        findings.append(Finding(
            id="",
            stage="emulation",
            title=f"radamsa file-format fuzzing crash #{i}",
            cwe="CWE-20",
            severity="HIGH",
            component=f"binary:parser",
            evidence=f"radamsa crash: rc={rc}  input_size={os.path.getsize(crash_path) if os.path.exists(crash_path) else '?'}",
            confirmation="PLAUSIBLE",
            emulation_trace=crash_out[:1000],
            manual_steps=[
                f"Reproduce: {qemu} {path} < {crash_path}",
                "Confirm crash reproduces",
                "Attach GDB to measure PC offset",
            ],
            runtime_flag="PLAUSIBLE_UNEMULATED",
            runtime_test_hint="Feed crashing input to real device parser; attach JTAG/GDB",
        ))

    return findings


def _run(cmd: list, timeout: int = 60) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return (r.stdout + r.stderr).decode(errors="replace"), r.returncode
    except subprocess.TimeoutExpired:
        return "[timeout]", -1
    except Exception as exc:
        return f"[error: {exc}]", -1
