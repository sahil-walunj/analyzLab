
"""
Backend wrapper for GUI with strict run isolation.
Each wrapper creates a unique run directory (analysis_out/<mode>_<timestamp>)
and produces only artifacts for that run.
"""

import os
import time
import shutil
from pathlib import Path

from script import (
    run_memory_monitor,
    run_syscall_monitor,
    run_network_syscall_monitor,
    run_file_access_monitor,
    summarize,
    plot_memory_segments,
    plot_syscall_counts,
    plot_network_syscall_usage,
)


def _make_run_dir(base="analysis_out", mode="run"):
    base = Path(base)
    base.mkdir(exist_ok=True)
    stamp = int(time.time() * 1000)
    run_dir = base / f"{mode}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def _safe_text(obj):
    try:
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("utf-8", errors="ignore")
        return str(obj)
    except Exception:
        return str(obj)


def run_memory_analysis(exe, args="", input_file=None, timeout=30):
    cmd = [exe] + (args.split() if args else [])
    result = run_memory_monitor(cmd, input_file=input_file, timeout=timeout)

    run_dir = _make_run_dir(mode="memory")
    mem_png = plot_memory_segments(result["samples"], run_dir)

    metrics = summarize(result["samples"])
    return {
        "mode": "memory",
        "returncode": result["returncode"],
        "elapsed": result.get("elapsed"),
        "stdout": _safe_text(result.get("stdout", "")),
        "stderr": _safe_text(result.get("stderr", "")),
        "metrics": metrics,
        "samples": result["samples"],
        "analysis_out": str(run_dir),
        "memory_png": mem_png,
        "syscall_png": None,
        "network_png": None,
        "file_access": None,
        "strace": None,
    }


def run_syscall_analysis(exe, args="", input_file=None, timeout=30):
    cmd = [exe] + (args.split() if args else [])
    result = run_syscall_monitor(cmd, input_file=input_file, timeout=timeout)

    run_dir = _make_run_dir(mode="syscall")
    generic_dir = Path(result.get("analysis_out", "analysis_out"))
    src = generic_dir / "strace_summary.txt"
    strace_text = result.get("strace")
    if src.exists():
        try:
            shutil.move(str(src), str(run_dir / src.name))
            strace_text = (run_dir / src.name).read_text(errors="ignore")
        except Exception:
            pass

    mem_png = plot_memory_segments(result["samples"], run_dir)
    syscall_png = plot_syscall_counts(strace_text, run_dir) if strace_text else None

    metrics = summarize(result["samples"])
    return {
        "mode": "syscall",
        "returncode": result["returncode"],
        "elapsed": result.get("elapsed"),
        "stdout": _safe_text(result.get("stdout", "")),
        "stderr": _safe_text(result.get("stderr", "")),
        "metrics": metrics,
        "samples": result["samples"],
        "analysis_out": str(run_dir),
        "memory_png": mem_png,
        "syscall_png": syscall_png,
        "network_png": None,
        "file_access": None,
        "strace": strace_text,
    }

def run_network_syscall_analysis(exe, args="", input_file=None, timeout=30):
    cmd = [exe] + (args.split() if args else [])
    exe_dir = os.path.dirname(exe)
    result = run_network_syscall_monitor(cmd, input_file=input_file, timeout=timeout,cwd=exe_dir)

    run_dir = _make_run_dir(mode="network_syscalls")
    generic_dir = Path(result.get("analysis_out", "analysis_out"))
    src = generic_dir / "net_strace.txt"
    net_text = result.get("strace")
    if src.exists():
        try:
            shutil.move(str(src), str(run_dir / src.name))
            net_text = (run_dir / src.name).read_text(errors="ignore")
        except Exception:
            pass

    net_png = plot_network_syscall_usage(result.get("parsed_network", []), run_dir)

    return {
        "mode": "network_syscalls",
        "returncode": result["returncode"],
        "elapsed": result.get("elapsed"),
        "stdout": _safe_text(result.get("stdout", "")),
        "stderr": _safe_text(result.get("stderr", "")),
        "metrics": {},
        "samples": [],
        "analysis_out": str(run_dir),
        "memory_png": None,
        "syscall_png": None,
        "network_png": net_png,
        "file_access": None,
        "strace": net_text,
    }


def run_file_access_analysis(exe, args="", input_file=None, timeout=30):
    cmd = [exe] + (args.split() if args else [])
    exe_dir = os.path.dirname(exe)
    result = run_file_access_monitor(cmd, input_file=input_file, timeout=timeout,cwd=exe_dir)

    run_dir = _make_run_dir(mode="files")
    generic_dir = Path(result.get("analysis_out", "analysis_out"))
    src = generic_dir / "file_access.txt"
    text = result.get("file_access")
    if src.exists():
        try:
            shutil.move(str(src), str(run_dir / src.name))
            text = (run_dir / src.name).read_text(errors="ignore")
        except Exception:
            pass

    metrics = summarize(result.get("samples", []))
    return {
        "mode": "files",
        "returncode": result["returncode"],
        "elapsed": result.get("elapsed"),
        "stdout": _safe_text(result.get("stdout", "")),
        "stderr": _safe_text(result.get("stderr", "")),
        "metrics": metrics,
        "samples": [],      
        "analysis_out": str(run_dir),
        "memory_png": None,
        "syscall_png": None,
        "network_png": None,
        "file_access": text,
        "strace": None,
    } 
