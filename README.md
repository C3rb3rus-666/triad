TRIAD | Cross-Platform Asynchronous Post-Exploitation Framework BETA
TRIAD is a modular orchestrator engineered for stealth persistence and memory-resident operations. Designed with a decoupled architecture, it leverages native syscalls and asynchronous I/O to maintain a minimal footprint on both POSIX and Win32 environments.

Developed by: C3rb3rus-666

🏗 System Architecture
The framework is built upon a Unified Execution Bridge, allowing for platform-independent high-level logic while executing through low-level native engines.

Core Components
Orchestrator (The Nexus): An asyncio-driven event loop that manages task scheduling, prioritized telemetry feedback, and concurrent module execution without blocking the main TUI.

Abstraction Layer: Implements a strict interface for memory manipulation, bypassing the need for platform-specific conditional logic in top-level tactical modules.

Native Engines:

POSIX: Direct /proc interaction, ptrace hijacking for process injection, and systemd / cron service masquerading.

Win32: Manual mapping of PEs (Reflective Loading), direct Nt* internal syscalls to bypass User-Mode hooks, and WMI/COM event hijacking for stealthy triggers.

🛠 Technical Specifications
Memory-Resident Execution (Fileless)
TRIAD prioritizes fileless operation. Payloads are reflectively loaded into memory using custom bootstrap loaders, avoiding traditional execve or CreateProcess hooks monitored by modern EDR/AV solutions. This ensures that the framework's footprint remains strictly within the process's heap/stack space.

Asynchronous Telemetry & C2
The C2 bridge utilizes an asynchronous polling mechanism to minimize network anomalies and timing-based detection (Beaconing Jitter). Communication protocols are modular, supporting:

Obfuscated WebSockets: Traffic masquerading as standard HTTPS/WSS.

Raw Binary Streams: Custom protocol definitions for low-bandwidth or highly restricted environments.

Self-Healing Persistence Strategy
Unlike standard persistence, TRIAD implements a "Multi-Node Watchdog" logic. Multiple independent processes monitor the integrity of the infection vector, re-triggering deployment upon detection or removal of any single node, ensuring a resilient presence within the target infrastructure.

📂 Repository Structure
Plaintext
.
├── core/                # Platform-agnostic orchestration (AsyncIO Loop)
├── engines/             # Low-level OS-specific implementations
│   ├── linux/           # Syscalls, ptrace, and procfs-based modules
│   └── windows/         # Direct WinAPI, Nt* syscalls, and Registry/WMI
├── modules/             # Tactical modules (Looting, Pivoting, Stealth)
├── proto/               # Custom binary and obfuscated protocol definitions
└── cli.py               # Main entry point (Asynchronous TUI Console)
⚖️ License & Disclaimer
This framework is developed for educational and authorized security auditing purposes only. Use of this tool against targets without prior written consent is illegal
