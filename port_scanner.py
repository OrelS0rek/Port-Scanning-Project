import scapy.all as sc
import socket
from abc import ABC, abstractmethod
from typing import Callable, Iterable, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import time
import random

"""
כל הקוד של קובץ זה בעיקרון מיותר - הוא נועד ליצור סורקי פורטים כדי שבעזרתם נוכל ליצור את קבצי ה-csv שלנו,
אך ניתן לסרוק כבר בעזרת כלים רבים כמו nmap ועוד. הכתיבה פה בעיקר נועדה ללמידה האישית שלי - גם על מודולים בפייתון שלא הכרתי
וגם קצת על איך כל סוג סריקת רשת עובד
"""

RST_BIT = 0x04  # המקביל הביטי של דגל ״rst״ של פרוטוקול tcp
ICMP_UNREACHABLE = [1, 2, 3, 9, 10, 13]
SYN_ACK = 0x02 | 0x10


ScanResult = Dict[str, object]
class BaseScanner(ABC):
    def __init__(self,
                 target: str,
                 timeout: float = 1.0,
                 workers: int = 50,
                 result_callback: Optional[Callable[[ScanResult], None]] = None):
        self.target = target
        self.timeout = timeout
        self.workers = workers
        self.result_callback = result_callback
        self.results: List[ScanResult] = []
        self._stop = False


    @abstractmethod
    def scan_port_sync(self, port: int) -> ScanResult:
        raise NotImplementedError

    def scan_range_threaded(self, ports: Iterable[int]) -> List[ScanResult]:
        self._stop = False
        self.results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self._safe_scan, p): p for p in ports}
            try:
                for fut in as_completed(futures):
                    if self._stop:
                        for f in futures:
                            f.cancel()
                        break

                    try:
                        res = fut.result()
                    except Exception as e:
                        port = futures.get(fut)
                        res = {"ip": self.target, "port": port, "status": "error", "meta": {"error": str(e)}}

                    if res is not None:
                        self.results.append(res)
                        if self.result_callback:
                            try:
                                self.result_callback(res)
                            except Exception :
                                pass
            finally:
                pass
            return self.results

    def _safe_scan(self, port: int) -> ScanResult:
        try:
            start = time.time()
            res = self.scan_port_sync(port)
            res.setdefault("elapsed", time.time() - start)
            return res
        except Exception as e:
            return {"ip": self.target, "port": port, "status": "error", "meta": {"error": str(e)}}


    def stop(self):
        self._stop = True

    async def scan_range_async(self, ports: Iterable[int]) -> List[ScanResult]:
        loop = asyncio.get_running_loop()
        self._stop = False
        self.results = []
        sem = asyncio.Semaphore(self.workers)

        async def worker(port: int):
            async with sem:
                if self._stop:
                    return

                res = await loop.run_in_executor(None, self._safe_scan, port)
                if res is not None:
                    self.results.append(res)
                    if self.result_callback:
                        try:
                            self.result_callback(res)
                        except Exception:
                            pass

        await asyncio.gather(*(worker(p) for p in ports))
        return self.results

    def scan_ports(self, ports: Iterable[int], use_async: bool = False) -> List[ScanResult]:
        if use_async:

            raise RuntimeError("")
        return self.scan_range_threaded(ports)

    def clear_results(self):
        self.results = []

class UDPScanner(BaseScanner):
    def __init__(self, target: str,
                 timeout: float = 1.0,
                 workers: int = 50,
                 result_callback: Optional[Callable[[ScanResult], None]] = None):
        super().__init__(target,timeout,workers,result_callback)

    def scan_port_sync(self, port: int) -> ScanResult:
        """
        הפונקציה מבצעת סריקת udp באופן הבא:
        הפונקציה תשלח חבילת udp לport המבוקש,
        במידה ולא תקבל חבילה בחזרה (כיוון שudp אינו מבצע התחברות כמו tcp) - הסורק יחזיר שהפורט סגור/מפולטר
        במידה ותתקבל חבילה המכילה שכבת icmp מסוג 3 - קוד 3 (התשובה המודיעה על פורט סגור) - הסורק יחזיר שהפורט סגור
        במידה ותתקבל חבילה אחרת שגם היא מכילה icmp הפורט מפולטר
        במידה ותוחזר חבילה שאינה icmp - הפורט פתוח
        """
        start = time.time()
        udp_pkt = sc.IP(dst=self.target)/sc.UDP(dport=port)
        try:
            response = sc.sr1(udp_pkt, timeout=self.timeout, verbose=False)
            if response is None:
                status = "open|filtered"
                meta  = {}
            elif response.haslayer(sc.ICMP):
                icmp_layer = response.getlayer(sc.ICMP)
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    status = "closed"
                    meta = {}
                else:
                    status = "filtered"
                    meta = {}
            else:
                status = "open"
                meta= {}
            meta["elapsed"] = f"{time.time() - start}"
        except Exception as e:
            status = "error"
            meta = {"error": str(e)}
        return {"ip": self.target, "port": port, "status": status, "meta": meta}


class TCPConnectScanner(BaseScanner):
    def __init__(self, target: str,
                 timeout: float = 1.0,
                 workers: int = 50,
                 result_callback: Optional[Callable[[ScanResult], None]] = None):
        super().__init__(target,timeout,workers,result_callback)

    def scan_port_sync(self, port: int) -> ScanResult:
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target,port))
            status = "open|filtered"
            meta = {}
        except socket.timeout:
            status = "filtered"
            meta = {}
        except ConnectionRefusedError:
            status = "closed"
            meta = {}
        except Exception as e:
            status = "error"
            meta = {"error": str(e)}
        meta["elapsed"] = f"{time.time() - start}"
        return {"ip": self.target, "port": port, "status": status, "meta": meta}

class TCPXmasScanner(BaseScanner):
    def __init__(self, target: str,
                 timeout: float = 1.0,
                 workers: int = 50,
                 result_callback: Optional[Callable[[ScanResult], None]] = None):
        super().__init__(target,timeout,workers,result_callback)

    def scan_port_sync(self, port: int) -> ScanResult:
        start = time.time()
        #ניצור חבילת tcp עם הדגלים fin, psh, urg
        tcp_pkt = sc.IP (dst=self.target) / sc.TCP (dport=port, flags="FPU")
        try:
            response = sc.sr1(tcp_pkt, timeout=self.timeout, verbose=False)
            meta = {}
            if response is None:
                status = "open|filtered"
            else:
                if response.haslayer(sc.TCP):
                    tcp_layer = response.getlayer(sc.TCP)
                    meta["tcp_flags"] = tcp_layer.flags
                    meta["src_port"] = tcp_layer.sport
                    meta["dst_port"] = tcp_layer.dport
                    meta["ttl"] = response.ttl if hasattr(response, "ttl") else None

                    if (int(tcp_layer.flags) & RST_BIT) != 0:
                        status = "closed"
                    else:
                        status = "unexpected"


                elif response.haslayer(sc.ICMP):
                    icmp_layer = response.getlayer(sc.ICMP)
                    meta["icmp_code"] = int(icmp_layer.code)
                    meta["icmp_type"] = int(icmp_layer.type)
                    if int(icmp_layer.type) == 3 and int(icmp_layer.code) in ICMP_UNREACHABLE:
                        status = "filtered"

                    else:
                        status = "unexpected"
                else:
                    status = "unexpected"
                meta["flags"] = str(response.flags)
        except Exception as e:
            status = "error"
            meta = {"error": str(e)}
        meta["elapsed"] = f"{time.time() - start}"
        return {"ip": self.target, "port": port, "status": status, "meta": meta}


class TCPSynScanner(BaseScanner):
    def __init__(self, target: str,
                 timeout: float = 1.0,
                 workers: int = 50,
                 result_callback: Optional[Callable[[ScanResult], None]] = None):
        super().__init__(target,timeout,workers,result_callback)



    def scan_port_sync(self, port: int) -> dict:
        start = time.time()
        meta = {}

        syn_pkt = sc.IP(dst=self.target) / sc.TCP(dport=port, flags="S")
        try:
            response = sc.sr1(syn_pkt, timeout=self.timeout, verbose=False)
            if response is None:
                status = "filtered"
            else:

                if response.haslayer(sc.ICMP):
                    icmp = response.getlayer(sc.ICMP)
                    meta["icmp_type"] = int(icmp.type)
                    meta["icmp_code"] = int(icmp.code)
                    if int(icmp.type) == 3 and int(icmp.code) in ICMP_UNREACHABLE:
                        status = "filtered"
                    else:
                        status = "unexpected"

                elif response.haslayer(sc.TCP):
                    tcp = response.getlayer(sc.TCP)
                    meta["tcp_flags"] = int(tcp.flags)
                    meta["src_port"] = tcp.sport
                    meta["dst_port"] = tcp.dport

                    meta["ttl"] = int(response[sc.IP].ttl) if response.haslayer(sc.IP) else None


                    if int(tcp.flags) & RST_BIT:
                        status = "closed"

                    elif (int(tcp.flags) & SYN_ACK) == SYN_ACK:
                        status = "open"

                        rst = sc.IP(dst=self.target) / sc.TCP(sport=tcp.dport, dport=tcp.sport, flags="R",
                                                              seq=int(tcp.ack))

                        sc.send(rst, verbose=False)
                    else:

                        status = "unexpected"
                else:
                    status = "unexpected"

        except Exception as e:
            status = "error"
            meta = {"error": str(e)}
        meta["elapsed"] = f"{time.time() - start}"

        return {"ip": self.target, "port": port, "status": status, "meta": meta}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="סורק פורטים")
    parser.add_argument("target", help="כתובת ip של המטרה")
    parser.add_argument(
        "-p", "--ports", default="80,443", help="רשימה מופרדת בעזרת , (דוגמא: 80,443). טווח מופרד בעזרת - (דוגמא: 1-1024) "
    )
    parser.add_argument(
        "-t", "--type",
        choices=["syn", "connect", "udp", "xmas"],
        default="syn",
        help="Type of scan to perform"
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="פסק-זמן בין כל שליחה")
    parser.add_argument("--workers", type=int, default=50, help="מספר התהליכונים הבין-זמניים")
    args = parser.parse_args()

    ports = []
    for part in args.ports.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    scanner_cls = {
        "syn": TCPSynScanner,
        "connect": TCPConnectScanner,
        "udp": UDPScanner,
        "xmas": TCPXmasScanner,
    }[args.type]

    scanner = scanner_cls(target=args.target, timeout=args.timeout, workers=args.workers)

    print(f"\n[*] Starting {args.type.upper()} scan on {args.target} ({len(ports)} ports)\n")

    start_time = time.time()
    results = scanner.scan_ports(ports)
    elapsed = time.time() - start_time

    for res in results:
        port = res["port"]
        status = res["status"]
        meta = res.get("meta", {})
        print(f"Port {port:5d} -> {status:12s}  (meta: {meta})")

    print(f"\nScan finished in {elapsed:.2f} seconds.\n")

if __name__ == "__main__":
    main()
