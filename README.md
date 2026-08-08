# An-Autonomous-Tool-Augmented-AI-Framework-for-Linux-RTOS-Binary-Analysis
It combines static decompilation heuristics (Ghidra) and multi-engine dynamic emulation (QEMU/Unicorn) guided by a Cloud LLM orchestration loop to perform automated symbol recovery and vulnerability triage.



# FirmwareAgent 🛡️

> **An Autonomous, Tool-Augmented AI Agent Framework for Linux & VxWorks Binary Analysis.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-10.x%20%7C%2011.x-red.svg)](https://ghidra-sre.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**FirmwareAgent** is an automated reverse engineering and firmware triage framework. Unlike basic LLM wrappers that merely pass decompiled C snippets to a prompt, FirmwareAgent operates as a **ReAct (Reason + Act)** orchestration loop. It combines static decompilation heuristics, specialized RTOS symbol recovery, and dynamic emulation to perform contextual vulnerability assessment across **Linux ELFs** and **VxWorks RTOS** binary targets.

---

## 🛠️ Architecture Overview

FirmwareAgent bridges static disassemblers, multi-engine emulators, and Cloud LLMs into an autonomous analysis pipeline:
