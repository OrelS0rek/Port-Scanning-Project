import threading
import time
import random

from port_scanner import UDPScanner, TCPXmasScanner, TCPConnectScanner, TCPSynScanner

TARGET = "127.0.0.1"
PORTS = range(1, 1025)
RUN_TIME = 12

def start_scanners(scanner_classes, target, ports, run_time_seconds=10):
    instances = []
    threads = []

    for cls in scanner_classes:
        inst = cls(target=target)
        instances.append(inst)

    for inst in instances:
        t = threading.Thread(target=inst.scan_ports, args=(ports,), name=inst.__class__.__name__, daemon=True)
        t.start()
        threads.append(t)

        time.sleep(random.uniform(0.01, 0.2))


    time.sleep(run_time_seconds)

    for inst in instances:
        inst.stop()

    for t in threads:
        t.join(timeout=8)

if __name__ == "__main__":
    scanner_classes = [UDPScanner, TCPXmasScanner, TCPConnectScanner, TCPSynScanner]
    start_scanners(scanner_classes, target=TARGET, ports=PORTS, run_time_seconds=RUN_TIME)
