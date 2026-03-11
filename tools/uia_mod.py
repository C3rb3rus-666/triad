import subprocess
import sys
import tempfile
import glob
from pathlib import Path
from core.orchestrator import TriadOrchestrator
from core.bridge import EventType

# Ensure workspace root on sys.path (if run from tools/)
from pathlib import Path
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PS_SCRIPT = str(Path(__file__).resolve().parents[1] / 'tools' / 'uia_mod.ps1')


def _cleanup_temp_ps_scripts():
    td = tempfile.gettempdir()
    pattern = str(Path(td) / 'uia_mod_*.ps1')
    for p in glob.glob(pattern):
        try:
            Path(p).unlink()
        except Exception:
            pass


def run_uia_mod(process_name: str, target: str, replacement: str) -> bool:
    orch = TriadOrchestrator()
    orch.bridge._logger = orch.logger

    _cleanup_temp_ps_scripts()

    cmd = [
        'powershell',
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        PS_SCRIPT,
        process_name,
        target,
        replacement,
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        out = res.stdout.strip()
        err = res.stderr.strip()

        async def _publish_ok(process_name: str, replaced_text: str, message: str):
            await orch.bridge.publish_event(
                EventType.UI_MANIPULATION_SUCCESS,
                'local',
                {
                    'operation': 'uia_mod',
                    'process': process_name,
                    'target': target,
                    'replacement': replacement,
                    'message': message,
                    'process_name': process_name,
                    'replaced_text': replaced_text,
                },
                'tools.uia_mod',
            )

        async def _publish_err(outp, errp):
            await orch.bridge.publish_engine_error(
                target_id='local',
                exception_type='UIAModError',
                error_code=None,
                metadata={'stdout': outp, 'stderr': errp},
            )

        if res.returncode == 0:
            print(out)
            proc_name = 'notepad'
            replaced_text = 'HACKED_BY_TRIAD'
            try:
                import asyncio

                asyncio.run(_publish_ok(proc_name, replaced_text, out))
            except Exception:
                pass

            _cleanup_temp_ps_scripts()
            return True
        else:
            print('PS failed:', out, err)
            try:
                import asyncio

                asyncio.run(_publish_err(out, err))
            except Exception:
                pass
            _cleanup_temp_ps_scripts()
            return False
    except Exception as e:
        print('Exception running PS:', e)
        try:
            import asyncio

            asyncio.run(
                orch.bridge.publish_engine_error(
                    target_id='local',
                    exception_type=type(e).__name__,
                    error_code=None,
                    metadata={'error': str(e)},
                )
            )
        except Exception:
            pass
        _cleanup_temp_ps_scripts()
        return False


if __name__ == '__main__':
    ok = run_uia_mod()
    sys.exit(0 if ok else 2)
