"""
script.py
Core analysis engine for OS Analyzer.
"""

import argparse
import os
import shlex
import subprocess
import threading
import time
from pathlib import Path
import matplotlib.pyplot as plt

try:
    import psutil
except Exception:
    psutil = None

SAMPLE_INTERVAL = 0.01


def parse_proc_status(pid):
    path = f"/proc/{pid}/status"
    data = {}
    try:
        with open(path, "r") as f:
            for line in f:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()
    except FileNotFoundError:
        return None
    return data


def read_metric_field(status, key):
    if not status:
        return None
    v = status.get(key)
    if not v:
        return None
    try:
        return int(v.split()[0])
    except Exception:
        return None


class MonitorThread(threading.Thread):
    def __init__(self, pid, interval=SAMPLE_INTERVAL):
        super().__init__()
        self.pid = pid
        self.interval = interval
        self.running = True
        self.samples = []
        if psutil and psutil.pid_exists(pid):
            try:
                self._proc = psutil.Process(pid)
            except Exception:
                self._proc = None
        else:
            self._proc = None

    def run(self):
        while self.running:
            st = parse_proc_status(self.pid)
            if st is None:
                break

            rss = read_metric_field(st, "VmRSS")
            vsz = read_metric_field(st, "VmSize")
            data = read_metric_field(st, "VmData")
            stk = read_metric_field(st, "VmStk")

            cpu_time = None
            net_sent = None
            net_recv = None

            if self._proc:
                try:
                    c = self._proc.cpu_times()
                    cpu_time = c.user + c.system
                except Exception:
                    cpu_time = None
                try:
                    net = self._proc.net_io_counters()
                    if net:
                        net_sent = getattr(net, "bytes_sent", None)
                        net_recv = getattr(net, "bytes_recv", None)
                    else:
                        net_sent = net_recv = None
                except Exception:
                    net_sent = net_recv = None

            ts = time.time()
            self.samples.append((ts, rss, vsz, data, stk, cpu_time, net_sent, net_recv))
            time.sleep(self.interval)

    def stop(self):
        self.running = False


def run_memory_monitor(cmd, input_file=None, timeout=None):
    out_dir = Path("analysis_out").absolute()
    out_dir.mkdir(exist_ok=True)

    stdin = open(input_file, "rb") if input_file else None

    proc = subprocess.Popen(
        cmd,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=os.path.dirname(cmd[0]) 
    )

    monitor = MonitorThread(proc.pid)
    monitor.start()

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    monitor.stop()
    monitor.join()

    return {
        "returncode": proc.returncode,
        "elapsed": None if not hasattr(proc, "start_time") else None,
        "stdout": stdout,
        "stderr": stderr,
        "samples": monitor.samples,
        "analysis_out": str(out_dir),
        "strace": None,
        "file_access": None
    }


def run_syscall_monitor(cmd, input_file=None, timeout=None):
    out_dir = Path("analysis_out").absolute()
    out_dir.mkdir(exist_ok=True)

    strace_summary = out_dir / "strace_summary.txt"

    full_cmd = ["strace", "-c", "-o", str(strace_summary)] + cmd
    stdin = open(input_file, "rb") if input_file else None

    proc = subprocess.Popen(
        full_cmd,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=os.path.dirname(cmd[0])
    )

    monitor = MonitorThread(proc.pid)
    monitor.start()

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    monitor.stop()
    monitor.join()

    strace_text = None
    if strace_summary.exists():
        try:
            strace_text = strace_summary.read_text(errors="ignore")
        except Exception:
            strace_text = None

    return {
        "returncode": proc.returncode,
        "elapsed": None,
        "stdout": stdout,
        "stderr": stderr,
        "samples": monitor.samples,
        "analysis_out": str(out_dir),
        "strace": strace_text,
        "file_access": None
    }

def parse_network_strace(strace_text):
    """
    Parse the network-related strace output and extract per-line send/recv byte counts.

    Returns list of (seq_index, bytes_sent, bytes_received)
    where seq_index is an integer incremented per matched syscall line (simple timeline).
    """
    if not strace_text:
        return []

    lines = strace_text.splitlines()
    parsed = []
    seq = 0

    for line in lines:
        line = line.strip()
        if not line or "=" not in line:
            continue

        try:
            left, right = line.rsplit("=", 1)
            ret = right.strip().split()[0]
            ret_val = int(ret)
        except Exception:
            
            continue

        lower = line.lower()
        sent = 0
        recv = 0
        if lower.startswith("send") or " send(" in lower or " sendto(" in lower or " sendmsg(" in lower:
            if ret_val > 0:
                sent = ret_val
        elif lower.startswith("recv") or " recv(" in lower or " recvfrom(" in lower or " recvmsg(" in lower:
            if ret_val > 0:
                recv = ret_val
        else:
            continue

        parsed.append((seq, sent, recv))
        seq += 1

    return parsed


def run_network_syscall_monitor(cmd, input_file=None, timeout=None,cwd=None):
    out_dir = Path("analysis_out").absolute()
    out_dir.mkdir(exist_ok=True)

    logfile = out_dir / "net_strace.txt"
    
    full_cmd = ["strace", "-e", "trace=network", "-s", "0", "-o", str(logfile)] + cmd
    stdin = open(input_file, "rb") if input_file else None

    proc = subprocess.Popen(
        full_cmd,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=cwd
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    text = None
    if logfile.exists():
        try:
            text = logfile.read_text(errors="ignore")
        except Exception:
            text = None

    parsed = parse_network_strace(text)

    return {
        "returncode": proc.returncode,
        "elapsed": None,
        "stdout": stdout,
        "stderr": stderr,
        "parsed_network": parsed,   
        "analysis_out": str(out_dir),
        "strace": text,
        "file_access": None
    }


def run_file_access_monitor(cmd, input_file=None, timeout=None, cwd=None):
    out_dir = Path("analysis_out").absolute()
    out_dir.mkdir(exist_ok=True)

    logfile = out_dir / "file_access.txt"
    full_cmd = ["strace", "-e", "trace=file", "-s", "0", "-o", str(logfile)] + cmd
    stdin = open(input_file, "rb") if input_file else None

    proc = subprocess.Popen(
        full_cmd,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=cwd
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    text = None
    if logfile.exists():
        try:
            text = logfile.read_text(errors="ignore")
        except Exception:
            text = None

    return {
        "returncode": proc.returncode,
        "elapsed": None,
        "stdout": stdout,
        "stderr": stderr,
        "samples": [],  # explicit empty; no memory samples for file mode
        "analysis_out": str(out_dir),
        "strace": None,
        "file_access": text
    }


# PLOT helpers
def summarize(samples):
    if not samples:
        return {}
    max_rss = max((s[1] for s in samples if s[1] is not None), default=None)
    max_vsz = max((s[2] for s in samples if s[2] is not None), default=None)
    max_data = max((s[3] for s in samples if s[3] is not None), default=None)
    max_stk = max((s[4] for s in samples if s[4] is not None), default=None)
    last_cpu = max((s[5] for s in samples if s[5] is not None), default=None)

    return {
        "max_rss_kb": max_rss,
        "max_vsz_kb": max_vsz,
        "max_data_kb": max_data,
        "max_stack_kb": max_stk,
        "last_cpu_seconds": last_cpu,
    }


def plot_memory_segments(samples, out_dir):
    out_dir = Path(out_dir)
    out_path = out_dir / "memory_segments.png"
    try:
        filtered = [s for s in samples if all(x is not None for x in s[:5])]
        if not filtered:
            return None
        base = filtered[0][0]
        times = [s[0] - base for s in filtered]
        rss = [s[1] for s in filtered]
        vsz = [s[2] for s in filtered]
        data = [s[3] for s in filtered]
        stk = [s[4] for s in filtered]

        plt.figure(figsize=(9, 5))
        plt.plot(times, rss, label="RSS (kB)")
        plt.plot(times, data, label="Heap (VmData kB)")
        plt.plot(times, stk, label="Stack (VmStk kB)")
        plt.plot(times, vsz, label="VSZ (kB)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_path)
        plt.close()
        return str(out_path)
    except Exception:
        return None


def plot_syscall_counts(strace_text, out_dir):
    if not strace_text:
        return None
    out_dir = Path(out_dir)
    out_path = out_dir / "syscall_counts.png"
    try:
        lines = strace_text.strip().split("\n")
        header_idx = None
        for i, line in enumerate(lines):
            if line.strip().lower().endswith("syscall"):
                header_idx = i
                break
        if header_idx is None:
            return None
        syscall_data = {}
        for line in lines[header_idx + 1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                count = int(parts[3])
                syscall = parts[-1]
                if syscall != "total":
                    syscall_data[syscall] = count
            except Exception:
                continue
        if not syscall_data:
            return None
        items = sorted(syscall_data.items(), key=lambda x: x[1], reverse=True)[:20]
        names = [x[0] for x in items]
        counts = [x[1] for x in items]
        plt.figure(figsize=(10, 6))
        plt.bar(names, counts)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(out_path)
        plt.close()
        return str(out_path)
    except Exception:
        return None


def plot_network_syscall_usage(parsed_data, out_dir):
    out_dir = Path(out_dir)
    out_path = out_dir / "network_usage.png"
    try:
        if not parsed_data:
            return None
        times = [p[0] for p in parsed_data]
        sent = [p[1] for p in parsed_data]
        recv = [p[2] for p in parsed_data]


        plt.figure(figsize=(10, 5))
        plt.plot(times, sent, label="Bytes Sent (per syscall)")
        plt.plot(times, recv, label="Bytes Recv (per syscall)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_path)
        plt.close()
        return str(out_path)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--args", default="")
    ap.add_argument("--input")
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--mode", choices=["memory", "syscall", "network_syscalls", "files"], required=True)
    args = ap.parse_args()

    cmd = [args.exe] + shlex.split(args.args)

    if args.mode == "memory":
        res = run_memory_monitor(cmd, input_file=args.input, timeout=args.timeout)
        print("SUMMARY:", summarize(res["samples"]))
    elif args.mode == "syscall":
        res = run_syscall_monitor(cmd, input_file=args.input, timeout=args.timeout)
        print("SUMMARY:", summarize(res["samples"]))
    elif args.mode == "network_syscalls":
        res = run_network_syscall_monitor(cmd, input_file=args.input, timeout=args.timeout)
        print("PARSED NETWORK ENTRIES:", len(res.get("parsed_network") or []))
    elif args.mode == "files":
        res = run_file_access_monitor(cmd, input_file=args.input, timeout=args.timeout)
        print("FILE LOG LENGTH (chars):", len(res.get("file_access") or ""))


if __name__ == "__main__":
    main()
