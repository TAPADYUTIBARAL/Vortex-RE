"""
Stage 5 — Vulnerability List & Runtime Flags

Merges findings from all stages into a ranked, deduplicated list.
Assigns RESOLVED / NEEDS_RUNTIME dispositions.
Writes vuln_list.json and runtime_handoff.json.
"""

import json
import os
from dataclasses import asdict
from typing import List, Tuple

from models import Finding, SEVERITY_RANK, SEVERITY_ORDER


# ── Runtime flag decision rules ───────────────────────────────────────────────

_CRYPTO_ACCEL_KEYWORDS = [
    "crypto accelerator", "hardware aes", "hardware sha", "hsm",
    "se050", "atecc", "tpm", "hardware rng accelerator", "pkcs11",
]
_HARDWARE_PERIPH_KEYWORDS = [
    "spi", "i2c", "uart", "jtag", "swd", "dma",
    "hardware rng", "watchdog", "usb phy", "mmio",
]
_TIMING_KEYWORDS = [
    "timing", "race condition", "toctou", "side-channel", "hmac comparison",
    "timing attack",
]
_HARDWARE_IFACE_KEYWORDS = [
    "jtag", "uart", "debug port", "physical", "i2c bus", "spi sniff",
    "u-boot", "boot interrupt",
]
_BOOT_KEYWORDS = [
    "bootloader", "secure boot", "u-boot", "boot chain", "rom", "reset vector",
]


def _assign_runtime_flag(f: Finding) -> Tuple[str, str]:
    """Return (runtime_flag, runtime_test_hint) for a NEEDS_RUNTIME finding."""
    if f.runtime_flag:
        return f.runtime_flag, f.runtime_test_hint

    title_ev = (f.title + " " + f.evidence + " " + f.component).lower()

    if any(k in title_ev for k in _BOOT_KEYWORDS):
        return "BOOT_CHAIN", "Verify on real device boot sequence; attach debugger at reset"

    if any(k in title_ev for k in _HARDWARE_IFACE_KEYWORDS) and "uart" in title_ev:
        return ("HARDWARE_INTERFACE",
                "Connect UART adapter at correct baud; repeat exploit sequence at power-on")

    if any(k in title_ev for k in _HARDWARE_IFACE_KEYWORDS):
        return ("HARDWARE_INTERFACE",
                "Physical interface required; repeat with real hardware access")

    if any(k in title_ev for k in _TIMING_KEYWORDS):
        return ("TIMING_DEPENDENT",
                "Measure response-time variance with valid vs. invalid inputs on real silicon")

    if any(k in title_ev for k in _CRYPTO_ACCEL_KEYWORDS):
        return ("CRYPTO_ACCELERATOR",
                "Crypto hardware accelerator absent in QEMU; validate key material on silicon")

    if any(k in title_ev for k in _HARDWARE_PERIPH_KEYWORDS):
        return ("EMULATION_INCOMPLETE",
                "Hardware peripheral absent in QEMU; repeat on real device with GDB/JTAG")

    if "network" in title_ev or "tcp" in title_ev or "udp" in title_ev:
        return ("NETWORK_STACK_DIFF",
                "Repeat with real NIC; QEMU virtio-net may differ from target stack")

    if f.confirmation == "PLAUSIBLE" and not f.emulation_trace:
        return "PLAUSIBLE_UNEMULATED", "No emulation run succeeded; confirm all logic on device"

    if f.confirmation == "CONFIRMED":
        return "DEEPER_EXPLOIT", "Confirmed in emulation; real device may yield persistent / higher impact"

    return "PLAUSIBLE_UNEMULATED", "Requires on-device confirmation"


_RUNTIME_PRIORITY = {
    "DEEPER_EXPLOIT":       0,
    "EMULATION_INCOMPLETE": 1,
    "HARDWARE_INTERFACE":   2,
    "TIMING_DEPENDENT":     3,
    "NETWORK_STACK_DIFF":   4,
    "BOOT_CHAIN":           5,
    "CRYPTO_ACCELERATOR":   6,
    "PLAUSIBLE_UNEMULATED": 7,
}


def _runtime_sort_key(f: Finding) -> Tuple[int, int]:
    prio = _RUNTIME_PRIORITY.get(f.runtime_flag, 99)
    sev  = 4 - SEVERITY_RANK.get(f.severity, 0)
    return (prio, sev)


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedup_key(f: Finding) -> str:
    """Canonical key for deduplication — same vuln at same address.

    A3: use full title (not truncated) so two same-named functions at different
    addresses (e.g. strcpy() at 0x1234 vs 0x5678) don't collapse when both
    addresses are unknown ("?") and happen to share the same 40-char prefix.
    """
    addr_part = f.address if f.address and f.address != "?" else ""
    return f"{f.cwe}:{f.component}:{addr_part}:{f.title}"


def _merge_duplicates(findings: List[Finding]) -> List[Finding]:
    seen: dict = {}
    for f in findings:
        key = _dedup_key(f)
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            # Keep highest severity
            if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = f.severity
            # Keep best confirmation
            conf_rank = {"CONFIRMED": 2, "PLAUSIBLE": 1, "UNVERIFIED": 0}
            if conf_rank.get(f.confirmation, 0) > conf_rank.get(existing.confirmation, 0):
                existing.confirmation = f.confirmation
            # Merge evidence
            if f.evidence and f.evidence not in existing.evidence:
                existing.evidence += f"\n[{f.stage}] {f.evidence}"
            # Keep best exploit_score
            existing.exploit_score = max(existing.exploit_score, f.exploit_score)
            # Merge poc_script
            if f.poc_script and not existing.poc_script:
                existing.poc_script = f.poc_script
            # Merge ghidra decompile
            if f.ghidra_decompile and not existing.ghidra_decompile:
                existing.ghidra_decompile = f.ghidra_decompile
    return list(seen.values())


# ── CVSS estimation ───────────────────────────────────────────────────────────

_CVSS_BASE = {
    "CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 0.0,
}


def _estimate_cvss(f: Finding) -> float:
    """A4: CVSS estimation with attack-vector adjustment.

    Physical-access findings (HARDWARE_INTERFACE) drop by 2.0 — AV:P.
    Local-only findings (BOOT_CHAIN) drop by 1.5 — AV:L.
    Network-reachable findings (NETWORK_STACK_DIFF, DEEPER_EXPLOIT) keep full score.
    Confirmation status applies last.
    """
    base = _CVSS_BASE.get(f.severity, 5.0)

    title_ev = (f.title + " " + f.evidence + " " + f.component).lower()
    if f.runtime_flag == "HARDWARE_INTERFACE" or "physical" in title_ev:
        base = max(base - 2.0, 0.0)
    elif f.runtime_flag == "BOOT_CHAIN" or (
        "local" in title_ev and "network" not in title_ev
    ):
        base = max(base - 1.5, 0.0)

    if f.confirmation == "CONFIRMED":
        base = min(base + 0.2, 10.0)
    elif f.confirmation == "UNVERIFIED":
        base = max(base - 1.0, 0.0)

    return round(base, 1)


# ── Main entry point ──────────────────────────────────────────────────────────

def build_vuln_list(findings: List[Finding], triage, out_dir: str) -> dict:
    from models import TriageResult

    os.makedirs(out_dir, exist_ok=True)

    # Dedup
    deduped = _merge_duplicates(findings)

    # Assign IDs sequentially if missing
    counter = [0]
    for f in deduped:
        if not f.id:
            counter[0] += 1
            f.id = f"F-{counter[0]:03d}"

    # Assign dispositions and runtime flags
    for f in deduped:
        if f.confirmation == "CONFIRMED" and f.runtime_flag not in ("DEEPER_EXPLOIT",):
            f.disposition = "RESOLVED"
        else:
            f.disposition = "NEEDS_RUNTIME"
            flag, hint = _assign_runtime_flag(f)
            if not f.runtime_flag:
                f.runtime_flag = flag
            if not f.runtime_test_hint:
                f.runtime_test_hint = hint

        # CVSS
        f.cvss = _estimate_cvss(f)

    # Rank: severity → confirmation → stage depth
    stage_depth = {"static": 0, "ghidra": 1, "fs": 1, "dynamic": 2, "emulation": 3}
    deduped.sort(key=lambda f: (
        -(SEVERITY_RANK.get(f.severity, 0)),
        -({"CONFIRMED": 2, "PLAUSIBLE": 1, "UNVERIFIED": 0}.get(f.confirmation, 0)),
        -(stage_depth.get(f.stage, 0)),
    ))

    section_a = [f for f in deduped if f.disposition == "RESOLVED"]
    section_b = sorted(
        [f for f in deduped if f.disposition == "NEEDS_RUNTIME"],
        key=_runtime_sort_key,
    )

    # Console render
    _render_console(section_a, section_b)

    # Write vuln_list.json
    vl_path = os.path.join(out_dir, "vuln_list.json")
    with open(vl_path, "w") as fh:
        json.dump(
            {"section_a": [asdict(f) for f in section_a],
             "section_b": [asdict(f) for f in section_b]},
            fh, indent=2, default=str,
        )

    # Write runtime_handoff.json
    handoff = [_runtime_handoff_entry(f) for f in section_b]
    rh_path = os.path.join(out_dir, "runtime_handoff.json")
    with open(rh_path, "w") as fh:
        json.dump(handoff, fh, indent=2, default=str)

    print(f"[+] vuln_list.json        → {vl_path}")
    print(f"[+] runtime_handoff.json  → {rh_path}")

    return {
        "findings": deduped,
        "resolved": section_a,
        "needs_runtime": section_b,
        "chains": [],
    }


def _runtime_handoff_entry(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "cvss": f.cvss,
        "cwe": f.cwe,
        "component": f.component,
        "confirmation": f.confirmation,
        "runtime_flag": f.runtime_flag,
        "reason": f.runtime_test_hint,
        "runtime_test_hint": f.runtime_test_hint,
        "poc_partial": f.poc_script[:2000] if f.poc_script else "",
        "ghidra_decompile": f.ghidra_decompile[:3000] if f.ghidra_decompile else "",
        "emulation_trace": f.emulation_trace[:2000] if f.emulation_trace else "",
    }


# ── Console table renderer ────────────────────────────────────────────────────

W = 74

def _render_console(section_a: List[Finding], section_b: List[Finding]) -> None:
    print(f"\n{'═' * W}")
    print(" VULNERABILITY LIST")
    print(f"{'═' * W}")

    print(f"\n Section A — RESOLVED ({len(section_a)} findings, confirmed in emulation)")
    print(f" {'─' * 70}")
    if not section_a:
        print("  (none)")
    for f in section_a:
        print(f"\n  [{f.id}] {f.title}")
        print(f"         {f.severity:<10} {f.confirmation:<12} {f.cwe}")
        print(f"         {f.component}")
        if f.manual_steps:
            print(f"         Repro: {f.manual_steps[0]}")

    print(f"\n Section B — NEEDS_RUNTIME ({len(section_b)} findings)")
    print(f" {'─' * 70}")
    if not section_b:
        print("  (none)")
    for f in section_b:
        print(f"\n  [{f.id}] {f.title}")
        print(f"         {f.severity:<10} {f.confirmation:<12} {f.cwe}")
        print(f"         Runtime flag : {f.runtime_flag}")
        print(f"         Runtime test : {f.runtime_test_hint[:80]}")

    print(f"\n{'═' * W}\n")
