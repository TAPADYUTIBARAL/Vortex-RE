"""
Stage 4c — Exploit chaining logic.

Attempts two-finding chains to achieve higher combined impact.
Chain patterns (from agent.md):
  info_leak   + stack_overflow → bypass PIE → CRITICAL
  auth_bypass + update_handler → unsigned firmware injection → CRITICAL
  cmd_inject  + suid           → persistence
  hardcoded_cred + suid        → local root
"""

import os
from typing import List, Optional, Tuple

from models import Finding


# ── Chain detection ───────────────────────────────────────────────────────────

def _classify(f: Finding) -> str:
    title = f.title.lower()
    if "info" in title and "leak" in title:
        return "info_leak"
    if "auth bypass" in title or "cwe-287" in f.cwe.lower():
        return "auth_bypass"
    if "command injection" in title:
        return "cmd_inject"
    if "hardcoded credential" in title or "cwe-798" in f.cwe.lower():
        return "hardcoded_cred"
    if "stack" in title and "overflow" in title:
        return "stack_overflow"
    if "update" in title or "firmware" in title:
        return "update_handler"
    if "suid" in title:
        return "suid"
    if "format string" in title:
        return "format_string"
    return "other"


_CHAIN_RULES: List[Tuple[str, str, str, str, str]] = [
    # (a_type, b_type, combined_title, combined_cwe, combined_severity)
    ("info_leak", "stack_overflow",
     "Chain: Info Leak → ASLR bypass → Stack Overflow → Shell",
     "CWE-134+CWE-121", "CRITICAL"),
    ("auth_bypass", "update_handler",
     "Chain: Auth Bypass → Admin Update Endpoint → Unsigned Firmware Injection",
     "CWE-287+CWE-494", "CRITICAL"),
    ("cmd_inject", "suid",
     "Chain: Command Injection → SUID Escalation → Persistence",
     "CWE-78+CWE-269", "CRITICAL"),
    ("hardcoded_cred", "suid",
     "Chain: Hardcoded Credential SSH Login → SUID Local Root",
     "CWE-798+CWE-269", "CRITICAL"),
    ("format_string", "stack_overflow",
     "Chain: Format String Leak → Address Disclosure → Stack Overflow",
     "CWE-134+CWE-121", "CRITICAL"),
]


def attempt_chains(confirmed: List[Finding], triage, poc_dir: str) -> List[Finding]:
    """
    Try all chain rule combinations on confirmed findings.
    Returns chain Finding objects for any successful or plausible chains.
    """
    chain_findings = []
    classified = {f: _classify(f) for f in confirmed}

    for fa in confirmed:
        for fb in confirmed:
            if fa is fb:
                continue
            ca = classified[fa]
            cb = classified[fb]
            for a_type, b_type, title, cwe, severity in _CHAIN_RULES:
                if ca == a_type and cb == b_type:
                    chain = _build_chain(fa, fb, title, cwe, severity, triage, poc_dir)
                    if chain:
                        chain_findings.append(chain)

    return chain_findings


def _build_chain(fa: Finding, fb: Finding, title: str, cwe: str,
                 severity: str, triage, poc_dir: str) -> Optional[Finding]:
    """Build a chain Finding combining fa + fb."""
    chain_id = f"{fa.id}+{fb.id}"
    script = _chain_script(fa, fb, title, triage)

    # Write chain script
    script_path = os.path.join(poc_dir, f"chain_{fa.id}_{fb.id}.py")
    try:
        with open(script_path, "w") as fh:
            fh.write(script)
    except Exception:
        pass

    steps = [
        f"Step 1: Run {fa.id} PoC: python3 poc/{fa.id}.py  [{fa.title[:50]}]",
        f"Step 2: Pipe result into {fb.id} PoC with extracted addresses",
        f"Step 3: python3 poc/chain_{fa.id}_{fb.id}.py",
        "Step 4: Observe combined higher-impact outcome",
    ]

    return Finding(
        id="",
        stage="emulation",
        title=title,
        cwe=cwe,
        severity=severity,
        component=f"{fa.component} → {fb.component}",
        evidence=(f"Chain: [{fa.id}] {fa.title[:40]} → [{fb.id}] {fb.title[:40]}"),
        confirmation="PLAUSIBLE",
        poc_script=script,
        manual_steps=steps,
        exploit_chain=[fa.id, fb.id],
        runtime_flag="DEEPER_EXPLOIT",
        runtime_test_hint="Execute chain steps on real device to confirm combined impact",
        exploit_score=0.85,
    )


def _chain_script(fa: Finding, fb: Finding, title: str, triage) -> str:
    return f"""#!/usr/bin/env python3
# [re_agent] Auto-generated Chain PoC
# Chain   : {fa.id} → {fb.id}
# Title   : {title}
#
# Step 1: Run the first stage PoC to obtain primitive
# Step 2: Feed the output into the second stage PoC
#
# This script orchestrates the full chain.

import subprocess, sys

print("[*] Chain: {title}")

# Stage 1: {fa.id} — {fa.title[:60]}
print("[*] Running stage 1 PoC: poc/{fa.id}.py")
r1 = subprocess.run(
    ["python3", "poc/{fa.id}.py"],
    capture_output=True, text=True, timeout=30,
)
print(r1.stdout[:500])
if not r1.stdout:
    print("[-] Stage 1 produced no output — aborting chain")
    sys.exit(1)

# Extract leaked address / credential from stage 1 output
# FIXME: parse r1.stdout for the leaked value
leaked_value = None
for line in r1.stdout.splitlines():
    if "0x" in line:
        import re
        m = re.search(r"0x[0-9a-fA-F]{{6,}}", line)
        if m:
            leaked_value = m.group(0)
            break

print(f"[*] Stage 1 extracted: {{leaked_value}}")

# Stage 2: {fb.id} — {fb.title[:60]}
print("[*] Running stage 2 PoC: poc/{fb.id}.py with extracted value")
# FIXME: pass leaked_value as argument to fb PoC
r2 = subprocess.run(
    ["python3", "poc/{fb.id}.py", "--leaked", str(leaked_value or "")],
    capture_output=True, text=True, timeout=30,
)
print(r2.stdout[:500])

if "uid=0" in r2.stdout or "SUCCESS" in r2.stdout or "CONFIRMED" in r2.stdout:
    print("[+] CHAIN SUCCESS: combined exploit achieved higher impact")
else:
    print("[-] Chain not fully confirmed — see individual PoCs")
    print("[!] STOP: manual adjustment required; run on real device if QEMU limitation")
"""
