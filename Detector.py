#!/usr/bin/env python3
import argparse
import datetime as dt
import ipaddress
import os
import sys
import time

try:
    import psutil
except ImportError:
    sys.stderr.write(
        "[!] psutil not found. Install with: python3 -m pip install psutil\n"
    )
    sys.exit(1)

SUSPECT_BIN_NAMES = {
    "bash", "sh", "zsh", "dash", "ksh",
    "python", "python3", "perl",
    "nc", "ncat", "netcat", "socat"
}

LOCAL_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_local_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in LOCAL_NETS)
    except ValueError:
        return False

def choose_log_path() -> str:
    candidates = ["/var/log/revsh_monitor.log",
                  os.path.expanduser("~/revsh_monitor.log")]
    for p in candidates:
        try:
            with open(p, "a"):
                pass
            return p
        except Exception:
            continue
    # Fallback to cwd
    return os.path.abspath("revsh_monitor.log")

LOG_PATH = choose_log_path()

def log(line: str):
    ts = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    out = f"{ts} {line}"
    print(out)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(out + "\n")
    except Exception as e:
        print(f"[!] Failed to write log: {e}", file=sys.stderr)

def proc_cmdline_safe(p: psutil.Process) -> str:
    try:
        cmd = p.cmdline()
        return " ".join(cmd) if cmd else p.name()
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
        return p.name()
    except Exception:
        return "<unknown>"

def username_safe(p: psutil.Process) -> str:
    try:
        return p.username()
    except Exception:
        return "<unknown>"

def parent_name_safe(p: psutil.Process) -> str:
    try:
        par = p.parent()
        return f"{par.pid}:{par.name()}" if par else "<none>"
    except Exception:
        return "<unknown>"

def has_remote_established_conn(p: psutil.Process):
    """Return list of (laddr, raddr) for established, non-local TCP conns."""
    conns = []
    try:
        for c in p.connections(kind="inet"):
            if c.status != psutil.CONN_ESTABLISHED:
                continue
            if not c.raddr:
                continue
            r_ip = c.raddr.ip
            if is_local_ip(r_ip):
                continue
            l = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            r = f"{c.raddr.ip}:{c.raddr.port}"
            conns.append((l, r))
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
        pass
    return conns

def looks_like_shell_or_tool(p: psutil.Process) -> bool:
    try:
        nm = p.name().lower()
    except Exception:
        nm = ""
    if nm in SUSPECT_BIN_NAMES:
        return True
    # Also check first argv token if available
    try:
        cmd = p.cmdline()
        if cmd:
            base = os.path.basename(cmd[0].lower())
            if base in SUSPECT_BIN_NAMES:
                return True
    except Exception:
        pass
    return False

def scan_once(kill: bool=False):
    alerts = 0
    for p in psutil.process_iter(attrs=[], ad_value=None):
        try:
            if not looks_like_shell_or_tool(p):
                continue
            conns = has_remote_established_conn(p)
            if not conns:
                continue

            alerts += 1
            info = {
                "pid": p.pid,
                "name": p.name(),
                "user": username_safe(p),
                "parent": parent_name_safe(p),
                "cmd": proc_cmdline_safe(p),
                "conns": conns,
            }
            log(f"[ALERT] Suspicious process pid={info['pid']} user={info['user']} "
                f"name={info['name']} parent={info['parent']} cmd=\"{info['cmd']}\" "
                f"remote_conns={info['conns']}")
            if kill:
                try:
                    p.terminate()
                    gone, alive = psutil.wait_procs([p], timeout=2)
                    if alive:
                        p.kill()
                    log(f"[ACTION] Terminated pid={info['pid']}")
                except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                    log(f"[ACTION] Failed to terminate pid={info['pid']}: {e}")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            # Running with sudo provides better visibility
            continue
        except Exception as e:
            log(f"[!] Error inspecting a process: {e}")
    return alerts

def main():
    ap = argparse.ArgumentParser(
        description="Monitor for suspicious shell-like processes with remote TCP connections (defensive use)."
    )
    ap.add_argument("--interval", type=float, default=5.0,
                    help="Seconds between scans (default: 5)")
    ap.add_argument("--once", action="store_true",
                    help="Scan only once and exit")
    ap.add_argument("--kill", action="store_true",
                    help="Attempt to terminate flagged processes (use with caution).")
    args = ap.parse_args()

    log(f"[INFO] Starting reverse-shell defensive monitor. Logging to {LOG_PATH}")
    if args.once:
        scan_once(kill=args.kill)
        return

    try:
        while True:
            scan_once(kill=args.kill)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log("[INFO] Stopped by user.")

if __name__ == "__main__":
    main()
