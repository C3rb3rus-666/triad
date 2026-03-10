# triad | Cross-Platform Asynchronous Post-Exploitation Framework

![License: MIT](https://img.shields.io/badge/License-MIT-000000?style=flat-square)
![Stage: Alpha](https://img.shields.io/badge/Stage-Alpha-red?style=flat-square)
![Arch: x86_64](https://img.shields.io/badge/Arch-x64-blue?style=flat-square)

**triad** is a modular orchestrator engineered for stealth persistence and memory-resident operations. Designed with a decoupled architecture, it leverages native syscalls and asynchronous I/O to maintain a minimal footprint on both POSIX and Win32 environments.

Developed by **C3rb3rus-666**.

---

## 🏗 System Architecture

The framework is built upon a **Unified Execution Bridge**, allowing for platform-independent high-level logic while executing through low-level native engines.

### Core Components
* **Orchestrator (The Nexus):** An `asyncio`-driven event loop that manages task scheduling and prioritized telemetry feedback.
* **Abstraction Layer:** Implements a strict interface for memory manipulation, bypassing the need for platform-specific conditional logic in top-level modules.
* **Native Engines:**
    * **POSIX:** Direct `/proc` interaction, `ptrace` hijacking, and `systemd` service masquerading.
    * **Win32:** Manual mapping of PEs, `Nt*` internal syscalls, and WMI/COM event hijacking.

---

## 🛠 Technical Specifications

### Memory-Resident Execution
`triad` prioritizes fileless operation. Payloads are reflectively loaded into memory, avoiding traditional `execve` or `CreateProcess` hooks monitored by EDR solutions.

### Asynchronous Telemetry
The C2 bridge utilizes an asynchronous polling mechanism to minimize network anomalies. Communication protocols are modular, supporting obfuscated WebSockets and raw binary streams.

### Persistence Strategy
Unlike standard persistence, `triad` implements a "Self-Healing" logic. Multiple watchdog processes monitor the integrity of the infection vector, re-triggering deployment upon detection or removal of a single node.

---

## 📂 Repository Structure

```text
.
├── core/                # Platform-agnostic orchestration logic
├── engines/             # Low-level OS-specific implementations
│   ├── linux/           # Syscalls and procfs-based modules
│   └── windows/         # Direct WinAPI and Registry manipulation
├── modules/             # Tactical modules (Looting, Pivoting, Stealth)
├── proto/               # Custom binary protocol definitions
└── cli.py               # Main entry point (Asynchronous TUI)
