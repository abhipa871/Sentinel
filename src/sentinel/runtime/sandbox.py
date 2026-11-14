"""Fixed-code synthetic worker, not a sandbox for arbitrary/hostile Python."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .policy import FIXTURES, PolicyError


def _windows_job(process):
    import ctypes
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class Extended(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", Basic),
            ("IoInfo", IO),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    limits = Extended()
    limits.BasicLimitInformation.LimitFlags = 0x2 | 0x8 | 0x100 | 0x2000
    limits.BasicLimitInformation.PerProcessUserTimeLimit = 20_000_000
    limits.BasicLimitInformation.ActiveProcessLimit = 1
    limits.ProcessMemoryLimit = 128 * 1024 * 1024
    if (
        not job
        or not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
        or not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(int(process._handle)))
    ):
        if job:
            kernel.CloseHandle(job)
        raise PolicyError("Unable to establish mock process resource limits")
    return lambda: kernel.CloseHandle(job)


def verify_fixture(fixture_id):
    if fixture_id not in FIXTURES:
        raise PolicyError("Unapproved fixture")
    worker = Path(__file__).resolve().parents[1] / "verification" / "mock_tests.py"
    # No repository paths, source, generated code, credentials, or arbitrary arguments enter this process.
    environment = {k: os.environ[k] for k in ("SYSTEMROOT", "WINDIR") if k in os.environ}
    with tempfile.TemporaryDirectory(prefix="sentinel-mock-") as workdir:
        executable = getattr(sys, "_base_executable", sys.executable)
        process = subprocess.Popen(
            [executable, "-I", "-S", str(worker)],
            cwd=workdir,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        close_job = None
        try:
            if os.name == "nt":
                close_job = _windows_job(process)
            output, _error = process.communicate(fixture_id + "\n", timeout=5)
            if process.returncode or len(output) > 10_000:
                raise PolicyError("Synthetic worker failed")
            result = json.loads(output)
            result["isolation"] = {
                "interpreter": "isolated",
                "network": "denied_by_audit_hook_in_fixed_worker",
                "wall_seconds": 5,
                "cpu_seconds": 2,
                "memory_mb": 128,
                "arbitrary_code_supported": False,
            }
            return result
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            if close_job:
                close_job()
