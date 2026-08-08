"""
Claude API integration for LLM-assisted analysis and report generation.
"""
import os
import json
from .detector import BinaryInfo
from .mcu import MCUInfo


def analyze_with_llm(
    info: BinaryInfo,
    os_type: str,
    controller_name: str,
    mcu: MCUInfo,
    strings_data: dict,
    binwalk_data: dict,
    r2_data: dict,
    readelf_data: dict | None,
    extraction_result: dict,
    rtos_fingerprint: dict,
    vector_table: dict | None,
    file_type: str,
) -> str:
    try:
        import anthropic
    except ImportError:
        return "[anthropic package not installed — skipping LLM analysis]"

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "[ANTHROPIC_API_KEY not set — skipping LLM analysis]"

    client = anthropic.Anthropic(api_key=api_key)
    context = _build_context(
        info, os_type, controller_name, mcu,
        strings_data, binwalk_data, r2_data, readelf_data,
        extraction_result, rtos_fingerprint, vector_table, file_type,
    )

    os_label = "RTOS firmware" if os_type == "RTOS" else "bare-metal firmware"
    system = (
        f"You are an expert embedded systems security analyst specializing in "
        f"{os_label} reverse engineering and vulnerability research. "
        f"The target runs on {mcu.description}. "
        f"Analyze the provided binary metadata and produce a concise, technical, "
        f"security-focused report. Do not pad with generic advice."
    )

    rtos_section = ""
    if os_type == "RTOS":
        rtos_section = """
## RTOS Analysis
Identify the RTOS, version if possible, task names, scheduler configuration,
heap usage, IPC primitives used (queues, semaphores, mutexes), and any
security-relevant RTOS misconfigurations (stack overflow detection disabled,
privileged tasks, etc.).
"""

    baremetal_section = ""
    if os_type == "BAREMETAL":
        baremetal_section = """
## Bare-Metal Analysis
Comment on the vector table (reset handler, fault handlers), peripheral usage
inferred from MMIO addresses, startup code patterns, and any HAL/BSP artifacts.
Flag missing fault handlers (handler pointing to 0 or looping to self).
"""

    prompt = f"""Analyze this {os_label} binary targeting {controller_name} and produce a structured report.

BINARY METADATA:
{context}

Produce a report with these exact sections:

## Summary
Binary type, architecture, target controller, apparent purpose, and confidence level.

## Architecture & Memory Layout
Load address, entry point, segments, flash/RAM usage observations.
{rtos_section}{baremetal_section}
## Embedded Filesystems & Containers
What was found and extracted, and what the extracted content reveals.

## Interesting Strings & Artifacts
Credentials, URLs, version strings, debug messages, error strings. Quote them verbatim.

## Functions & Code Patterns
Key functions, call patterns, suspicious logic, hardcoded values in code.

## Security Findings
Vulnerabilities and risks — rate each as CRITICAL / HIGH / MEDIUM / LOW.
Include: insecure functions, hardcoded secrets, debug interfaces, missing
protections (no MPU, no stack canary), exposed interfaces.

## Recommendations
Top 3–5 actionable next steps for deeper analysis or remediation.
"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}],
            system=system,
        )
        return response.content[0].text
    except Exception as exc:
        return f"[LLM analysis failed: {exc}]"


def _build_context(
    info: BinaryInfo,
    os_type: str,
    controller_name: str,
    mcu: MCUInfo,
    strings_data: dict,
    binwalk_data: dict,
    r2_data: dict,
    readelf_data: dict | None,
    extraction_result: dict,
    rtos_fingerprint: dict,
    vector_table: dict | None,
    file_type: str,
) -> str:
    parts: list[str] = []

    parts += [
        f"File            : {os.path.basename(info.path)}",
        f"Format          : {info.format}",
        f"Size            : {info.size:,} bytes",
        f"OS Type         : {os_type}",
        f"Controller      : {controller_name}  ({mcu.description})",
        f"Architecture    : {mcu.r2_arch} {mcu.r2_bits}-bit"
        + (f"  cpu={mcu.r2_cpu}" if mcu.r2_cpu else ""),
        f"Flash base      : {hex(mcu.flash_base)}",
        f"RAM base        : {hex(mcu.ram_base)}",
        f"file(1) output  : {file_type}",
        "",
    ]

    if info.metadata:
        parts += ["=== File Metadata ===",
                  json.dumps(info.metadata, indent=2, default=str), ""]

    if vector_table and "vectors" in vector_table:
        parts += ["=== Cortex-M Vector Table ===",
                  f"Initial SP      : {vector_table['initial_sp']}",
                  f"Reset handler   : {vector_table['reset_handler']}"]
        for v in vector_table["vectors"][:16]:
            parts.append(f"  [{v['index']:2d}] {v['name']:<24} {v['address']}")
        parts.append("")

    if rtos_fingerprint.get("detected"):
        parts += ["=== RTOS Fingerprint ===",
                  f"Detected RTOS   : {rtos_fingerprint['detected']}",
                  f"Confidence      : {rtos_fingerprint.get('confidence', '?')}"]
        for rtos, sigs in rtos_fingerprint.get("candidates", {}).items():
            parts.append(f"  {rtos}: {', '.join(sigs)}")
        parts.append("")
    elif os_type == "RTOS":
        parts += ["=== RTOS Fingerprint ===",
                  "No known RTOS signatures matched.", ""]

    parts += ["=== Interesting Strings ===",
              f"Total extracted : {strings_data.get('total', 0)}",
              f"Interesting     : {len(strings_data.get('interesting', []))}"]
    parts.extend(strings_data.get("interesting", [])[:100])
    parts.append("")

    sig_text = binwalk_data.get("signatures", "").strip()
    if sig_text:
        parts += ["=== Binwalk Signatures ===", sig_text[:2500], ""]

    fs_found = extraction_result.get("filesystems_found", 0)
    if fs_found:
        parts += [f"=== Extraction Results ({fs_found} filesystem(s) found) ==="]
        for r in extraction_result.get("dedicated_results", []):
            parts.append(
                f"  {r['fs_type']:<12} @ {r['offset']:<12}  "
                f"status={r['extraction'].get('status', '?')}"
            )
        parts.append("")

    if readelf_data:
        parts += ["=== ELF Headers ===", readelf_data.get("headers", "")[:1000],
                  "=== ELF Sections ===", readelf_data.get("sections", "")[:1500],
                  "=== Dynamic ===", readelf_data.get("dynamic", "")[:800], ""]

    fns = r2_data.get("functions", [])
    if fns:
        parts += [f"=== Radare2 Functions ({len(fns)} found) ==="]
        parts.extend(fns[:30])
        parts.append("")

    r2_strings = r2_data.get("strings", [])
    if r2_strings:
        parts += ["=== Radare2 Strings ==="]
        parts.extend(r2_strings[:30])
        parts.append("")

    return "\n".join(str(p) for p in parts)
