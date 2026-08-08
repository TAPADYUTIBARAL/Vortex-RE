# Vortex-RE 🛡️

> **An Autonomous, Tool-Augmented AI Agent Framework for Linux & VxWorks Binary Analysis.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-10.x%20%7C%2011.x-red.svg)](https://ghidra-sre.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**FirmwareAgent** is an automated reverse engineering and firmware triage framework. Unlike basic LLM wrappers that merely pass decompiled C snippets to a prompt, FirmwareAgent operates as a **ReAct (Reason + Act)** orchestration loop. It combines static decompilation heuristics, specialized RTOS symbol recovery, and dynamic emulation to perform contextual vulnerability assessment across **Linux ELFs** and **VxWorks RTOS** binary targets.

---

## 🛠️ Architecture Overview

FirmwareAgent bridges static disassemblers, multi-engine emulators, and Cloud LLMs into an autonomous analysis pipeline:

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
git clone [https://github.com/your-username/FirmwareAgent.git](https://github.com/your-username/FirmwareAgent.git)
cd FirmwareAgent

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
