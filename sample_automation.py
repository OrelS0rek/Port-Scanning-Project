#!/usr/bin/env python3
"""

נכתב על ידי צאט גיפיטי
sample_automation.py

Option A automated dataset collector:
- sniff on interfaces en0 and lo0 (tcpdump)
- alternate normal and scan sessions
- run a variety of nmap scans (SYN, Connect, UDP, Xmas, Null, FIN)
- save labeled pcap files in ./dataset/<label>/
- run for TOTAL_MINUTES (default 30)

USAGE:
    sudo python3 sample_automation.py
"""

import os
import time
import subprocess
import signal
import random
from datetime import datetime
from pathlib import Path

# -----------------------
# Configuration
# -----------------------
INTERFACES = ["en0", "lo0"]        # sniff these interfaces
TOTAL_MINUTES = 30                 # total run time (minutes)
NORMAL_SESSION_SECONDS = 60        # how long a single normal capture lasts
SCAN_GAP_SECONDS = 5               # pause between stop tcpdump and running nmap
POST_SCAN_WAIT = 3                 # seconds to allow nmap/tcpdump to flush
OUTPUT_DIR = Path("dataset")       # output root
PCAP_PER_SESSION = True            # write one pcap per interface per session
TCPDUMP_CMD = "tcpdump"            # path to tcpdump (assumes in PATH)
NMAP_CMD = "nmap"                  # path to nmap

# nmap target interface to read IP from (we will try to get IP of en0)
IPIF = "en0"

# scan configurations: (label, nmap_flags, port_range, timing)
SCAN_CONFIGS = [
    ("syn", "-sS -Pn", "1-200", "-T4"),
    ("connect", "-sT -Pn", "1-200", "-T4"),
    ("udp", "-sU -Pn", "1-200", "-T4"),
    ("xmas", "-sX -Pn", "1-200", "-T4"),
    ("null", "-sN -Pn", "1-200", "-T4"),
    ("fin", "-sF -Pn", "1-200", "-T4"),
]

# You can tune these if you want more/less aggressive scanning
RANDOM_SLEEP_AFTER_SESSION = (2, 6)  # random pause between sessions (seconds)

# -----------------------
# Helpers
# -----------------------
def ensure_dirs():
    OUTPUT_DIR.mkdir(exist_ok=True)
    (OUTPUT_DIR / "normal").mkdir(exist_ok=True)
    for label, _, _, _ in SCAN_CONFIGS:
        (OUTPUT_DIR / f"scan_{label}").mkdir(exist_ok=True)

def get_timestamp():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%S")

def get_if_addr(ifname):
    """
    Try to get interface IP address using scapy (if available) or fallback to socket trick.
    """
    try:
        # lazy import to avoid failing if scapy not installed
        from scapy.all import get_if_addr
        return get_if_addr(ifname)
    except Exception:
        # fallback: attempt to use socket to get primary IP (not interface-specific)
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # connect to public DNS to get primary outbound IP
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return None
        finally:
            s.close()

def start_tcpdump(iface, outpath):
    """
    Start tcpdump writing to outpath (returns subprocess).
    Using -U (packet-buffered output), -s 0 capture full packet, -n no name resolution.
    """
    cmd = [TCPDUMP_CMD, "-i", iface, "-w", str(outpath), "-U", "-s", "0", "-n"]
    # suppress tcpdump stdout/stderr
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    return proc

def stop_tcpdump(proc):
    """Stop tcpdump subprocess cleanly (SIGINT then wait)."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

def run_nmap(target_ip, flags, ports, timing_flag):
    """
    Run nmap with given flags; returns subprocess CompletedProcess.
    Flags e.g. "-sS -Pn", ports "1-200", timing "-T4"
    """
    cmd = [NMAP_CMD] + flags.split() + [timing_flag, "-p", ports, target_ip]
    # run and wait
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        return proc
    except subprocess.TimeoutExpired:
        return None

# -----------------------
# Main loop
# -----------------------
def main():
    print("[*] Starting automated dataset collector (Option A).")
    print("[*] Make sure you run this script with sudo/root privileges.")
    ensure_dirs()

    # determine target IP from interface IPIF
    target_ip = get_if_addr(IPIF)
    if not target_ip:
        print("[!] Could not determine IP of interface", IPIF)
        print("[!] Falling back to 127.0.0.1 (note: loopback scans won't appear on en0)")
        target_ip = "127.0.0.1"
    print("[*] Using target IP for scans:", target_ip)

    total_seconds = TOTAL_MINUTES * 60
    end_time = time.time() + total_seconds

    scan_idx = 0
    session_count = 0
    try:
        # We'll alternate: Normal -> Scan -> Normal -> Scan ...
        mode = "normal"
        while time.time() < end_time:
            session_count += 1
            ts = get_timestamp()
            print(f"\n=== Session #{session_count} ({mode}) @ {ts} ===")

            if mode == "normal":
                # Create tcpdump procs for each interface, recording to normal dir
                procs = []
                for iface in INTERFACES:
                    outfile = OUTPUT_DIR / "normal" / f"normal_{ts}_{iface}.pcap"
                    print(f"[*] Starting tcpdump on {iface} -> {outfile}")
                    p = start_tcpdump(iface, outfile)
                    procs.append((iface, p, outfile))

                # capture for NORMAL_SESSION_SECONDS
                remaining = NORMAL_SESSION_SECONDS
                while remaining > 0:
                    sleep_chunk = min(5, remaining)
                    time.sleep(sleep_chunk)
                    remaining -= sleep_chunk
                    print(f"    ... capturing normal, {remaining}s left", end="\r")

                # stop tcpdump procs
                for iface, p, outfile in procs:
                    print(f"\n[*] Stopping tcpdump on {iface}")
                    stop_tcpdump(p)

                # small random pause
                gap = random.uniform(*RANDOM_SLEEP_AFTER_SESSION)
                print(f"[*] Sleeping {gap:.1f}s after normal session")
                time.sleep(gap)

                # switch to scan next
                mode = "scan"

            elif mode == "scan":
                # pick a scan config cyclically
                label, flags, ports, timing = SCAN_CONFIGS[scan_idx % len(SCAN_CONFIGS)]
                scan_idx += 1

                print(f"[*] Preparing a '{label}' scan against {target_ip} ports {ports} flags {flags} {timing}")

                # start tcpdump on each interface writing to scan_label dir
                procs = []
                for iface in INTERFACES:
                    dirname = OUTPUT_DIR / f"scan_{label}"
                    dirname.mkdir(parents=True, exist_ok=True)
                    outfile = dirname / f"scan_{label}_{ts}_{iface}.pcap"
                    print(f"[*] Starting tcpdump on {iface} -> {outfile}")
                    p = start_tcpdump(iface, outfile)
                    procs.append((iface, p, outfile))

                # small gap to ensure tcpdump is ready
                time.sleep(SCAN_GAP_SECONDS)

                # run nmap
                print(f"[*] Running nmap ({label}) ...")
                result = run_nmap(target_ip, flags, ports, timing)
                if result is None:
                    print("[!] nmap timed out")
                else:
                    print(f"[*] nmap finished (rc={result.returncode}). stdout length {len(result.stdout)}")

                # wait a short time to ensure packets flushed to disk
                time.sleep(POST_SCAN_WAIT)

                # stop tcpdump procs
                for iface, p, outfile in procs:
                    print(f"[*] Stopping tcpdump on {iface}")
                    stop_tcpdump(p)

                # random small pause before next session
                gap = random.uniform(*RANDOM_SLEEP_AFTER_SESSION)
                print(f"[*] Sleeping {gap:.1f}s after scan session")
                time.sleep(gap)

                # switch to normal next
                mode = "normal"

            # small check if we're out of time
            if time.time() >= end_time:
                print("[*] Reached total run duration.")
                break

    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt received: stopping active tcpdump processes and exiting.")

    print("[*] Dataset collection finished.")
    print("[*] Files saved under:", OUTPUT_DIR.resolve())
    print("[*] Directory contents (summary):")
    for d in OUTPUT_DIR.iterdir():
        if d.is_dir():
            count = len(list(d.glob("*.pcap")))
            print(f"    {d.name}: {count} pcap(s)")

if __name__ == "__main__":
    main()
