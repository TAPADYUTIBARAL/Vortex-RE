"""Shared data models for the re_agent pipeline."""
from dataclasses import dataclass, field
from typing import Any, List


SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class TriageResult:
    format: str                     # elf, pe, raw_bin, intel_hex, dfu_stm32
    arch: str                       # arm, mips, x86, x86_64, aarch64, riscv
    bits: str                       # 32, 64, 16
    endian: str                     # little, big
    os_type: str                    # Linux, RTOS, Baremetal, Unknown
    mcu_match: str                  # MCU description string
    confidence: float               # 0.0 – 1.0
    load_address: int
    entry_point: int
    has_filesystem: bool
    extracted_path: str             # path to extracted FS root or ""
    binary_info: Any                # BinaryInfo from toolkit/detector.py
    mitigations: dict = field(default_factory=dict)
    # mitigations keys: nx (bool), canary (bool), pie (bool),
    #   relro ("no"|"partial"|"full"), fortify (bool), file (str)
    rtos_info: dict = field(default_factory=dict)
    vector_table: dict = field(default_factory=dict)


@dataclass
class Finding:
    id: str = ""                       # F-001, F-002, ...
    stage: str = ""                    # static | ghidra | fs | dynamic | emulation
    title: str = ""
    cwe: str = ""                      # CWE-120, CWE-798, ...
    severity: str = "MEDIUM"           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    component: str = ""               # "binary:0xADDR" or "path/to/file"
    evidence: str = ""                 # raw evidence string
    confirmation: str = "UNVERIFIED"  # CONFIRMED | PLAUSIBLE | UNVERIFIED
    emulation_trace: str = ""
    poc_script: str = ""               # full PoC source code
    poc_output: str = ""               # stdout from successful PoC execution
    manual_steps: List[str] = field(default_factory=list)
    exploit_chain: List[str] = field(default_factory=list)
    disposition: str = "NEEDS_RUNTIME" # RESOLVED | NEEDS_RUNTIME
    runtime_flag: str = ""
    # EMULATION_INCOMPLETE | TIMING_DEPENDENT | HARDWARE_INTERFACE |
    # NETWORK_STACK_DIFF | CRYPTO_ACCELERATOR | BOOT_CHAIN |
    # PLAUSIBLE_UNEMULATED | DEEPER_EXPLOIT
    runtime_test_hint: str = ""
    ghidra_decompile: str = ""
    address: str = ""                  # hex address string e.g. "0x0804a3c0"
    function_name: str = ""
    exploit_score: float = 0.0
    cvss: float = 0.0
    analysis_pipeline: str = ""  # "linux" | "vxworks" | "freertos" | "qnx"
