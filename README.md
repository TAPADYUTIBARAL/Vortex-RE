# Vortex-RE 🛡️

> **An Autonomous, Tool-Augmented AI Agent Framework for Linux & VxWorks Binary Analysis.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-10.x%20%7C%2011.x-red.svg)](https://ghidra-sre.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Vortex-RE** is an automated reverse engineering and firmware triage framework. Unlike basic LLM wrappers that merely pass decompiled C snippets to a prompt, Vortex-RE operates as a **ReAct (Reason + Act)** orchestration loop. It combines static decompilation heuristics, specialized RTOS symbol recovery, and dynamic emulation to perform contextual vulnerability assessment across **Linux ELFs** and **VxWorks RTOS** binary targets.

---

## 🛠️ Architecture Overview

Vortex-RE bridges static disassemblers, multi-engine emulators, and Cloud LLMs into an autonomous analysis pipeline:

flowchart TD
    subgraph Cloud LLM Engine ["Cloud LLM Engine (Reasoning Layer)"]
        LLM["Claude 3.5 Sonnet / GPT-4o / Gemini 1.5 Pro"]
    end

    subgraph Agent ["Agent Orchestrator (re_agent.py)"]
        ReAct["ReAct Decision & Tool Execution Loop"]
    end

    subgraph Engines ["Analysis & Execution Subsystems"]
        subgraph Ingestion ["Ingestion & Pre-processing"]
            BaseAddr["Base Address Detection"]
            Headers["ELF / Binary Header Analysis"]
            Extract["Filesystem Extraction (Binwalk / HRFS)"]
        end

        subgraph Static ["Static Analysis Engine"]
            Ghidra["Ghidra Headless Scripts"]
            Symbols["VxWorks Symbol Recovery"]
            Vulns["Vulnerability Pattern Scanners"]
        end

        subgraph Dynamic ["Dynamic Emulation Engine"]
            Unicorn["Unicorn Engine (Func Emulation)"]
            QEMU["QEMU (System / User Mode)"]
            GDB["Managed GDB Debugging & Crash Triage"]
        end
    end

    %% Flow Connections
    LLM <== "Structured Tool Calls & Responses" ==> ReAct
    
    ReAct --> Ingestion
    ReAct --> Static
    ReAct --> Dynamic

    %% Feedback Loops
    Ingestion -. "Binary Context" .-> ReAct
    Static -. "Decompilation & Candidate Flaws" .-> ReAct
    Dynamic -. "Crash Logs & Execution Traces" .-> ReAct

    %% Styling
    style Cloud LLM Engine fill:#f9f,stroke:#333,stroke-width:2px
    style Agent fill:#bbf,stroke:#333,stroke-width:2px
    style Ingestion fill:#dfd,stroke:#333,stroke-width:1px
    style Static fill:#ffd,stroke:#333,stroke-width:1px
    style Dynamic fill:#fdd,stroke:#333,stroke-width:1px

---

## ✨ Key Features

### 🔍 Specialized RTOS & VxWorks Analysis
* **Symbol Table Recovery:** Parses `sysSymTbl` structures and unstripped memory regions to reconstruct function names and global variables.
* **OS Primitive Identification:** Maps calls to `taskSpawn`, `taskInit`, semaphores (`semBCreate`), and message queues (`msgQCreate`).
* **Exposure Detection:** Automated heuristics for unauthenticated Target Server (WDB) interfaces, exposed debug shells, and ISR/Task stack overflow vulnerabilities.

### 🐧 Linux Binary & ELF Support
* **Attack Surface Mapping:** Traces untrusted inputs originating from network sockets (`recv`, `recvfrom`) down to dangerous string/memory sinks (`memcpy`, `sprintf`, `system`).
* **Protection Auditing:** Detects binary mitigations including NX/DEP, ASLR/PIE, Stack Canaries, and RELRO.

### ⚡ Dynamic Emulation & Verification
* **Multi-Engine Runtime:** Instruction-level emulation via **Unicorn Engine** and full/user-mode emulation via **QEMU**.
* **Crash Triage:** Automated input generation and harness execution to validate candidates identified during static analysis.

---

## 🚀 Quickstart

### Prerequisites

Ensure you have the following tools installed on your host system:

* **Python 3.10+**
* **Ghidra** (Set the `GHIDRA_INSTALL_DIR` environment variable)
* **QEMU** (`qemu-user` or `qemu-system` binaries in `$PATH`)
* **GDB** (with cross-architecture support if analyzing non-x86 binaries)

### 1. Installation

```bash
# Clone the repository
git clone [https://github.com/your-username/Vortex-RE.git](https://github.com/your-username/Vortex-RE.git)
cd Vortex-RE

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt


# .env file
ANTHROPIC_API_KEY="your-anthropic-api-key"
OPENAI_API_KEY="your-openai-api-key"
GHIDRA_INSTALL_DIR="/path/to/ghidra"

##📂 Repository Structure

├── re_agent.py              # Central agent orchestrator & execution loop
├── models.py                # Data structures & state management
├── vuln_list.py             # Vulnerability signature definitions
├── toolkit/                 # Ingestion, MCU heuristics, and LLM interface
│   ├── detector.py          # Binary format detection
│   ├── extractor.py         # Archive & filesystem extractor
│   └── llm.py               # Cloud LLM client API wrappers
├── ghidra_scripts/          # Generic Ghidra static analysis scripts
│   ├── FindAuthBypass.py    # Authentication check analysis
│   └── FindVulnPatterns.py  # Dangerous C function call detection
├── ghidra_scripts_vxworks/  # VxWorks-specific Ghidra analysis scripts
│   ├── VxSymbolTableParser.py # Symbol table parsing logic
│   └── FindVxWDBExposure.py   # WDB target server exposure checks
├── vxworks/                 # VxWorks extraction & load address helpers
└── emulation/               # Dynamic execution engines (Unicorn, QEMU, GDB)
