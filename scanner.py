import queue
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


PORT_SERVICE_MAP: dict[int, str] = {
    20: "FTP-Data",  21: "FTP",       22: "SSH",       23: "Telnet",
    25: "SMTP",      53: "DNS",        69: "TFTP",      80: "HTTP",
    110: "POP3",     111: "RPC",      119: "NNTP",     123: "NTP",
    135: "MSRPC",   137: "NetBIOS",   139: "NetBIOS",  143: "IMAP",
    161: "SNMP",    389: "LDAP",      443: "HTTPS",    445: "SMB",
    465: "SMTPS",   514: "Syslog",    587: "SMTP",     636: "LDAPS",
    993: "IMAPS",   995: "POP3S",    1080: "SOCKS",   1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP",    2049: "NFS",     2181: "Zookeeper",
    3306: "MySQL",  3389: "RDP",     5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis",  6443: "K8s-API", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 9300: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB",
}

HTTP_PROBE_PORTS: frozenset[int] = frozenset({80, 8080, 8008, 8888, 8081})


@dataclass
class ScanResult:
    host: str
    port: int
    status: str          # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    scan_time: float = 0.0


class ScanEngine:
    def __init__(self, result_queue: queue.Queue):
        self._result_queue = result_queue
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    # ── Banner grabbing ────────────────────────────────────────────────────

    def _grab_banner(self, sock: socket.socket, port: int) -> tuple[str, str]:
        service = PORT_SERVICE_MAP.get(port, "")
        try:
            sock.settimeout(2.0)
            if port in HTTP_PROBE_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 443 or port == 8443:
                return service or "HTTPS", "[SSL/TLS — encrypted, use HTTPS client]"
            # Receive response
            raw = sock.recv(1024)
            banner = raw.decode("utf-8", errors="ignore").strip()
            banner = " ".join(banner.split())[:120]   # collapse whitespace, cap length
            return service, banner
        except Exception:
            return service, ""

    # ── TCP Connect Scan ───────────────────────────────────────────────────

    def tcp_connect_scan(self, host: str, port: int, timeout: float) -> ScanResult:
        t0 = time.monotonic()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            elapsed = time.monotonic() - t0
            service, banner = self._grab_banner(sock, port)
            sock.close()
            return ScanResult(host, port, "open", service, banner, round(elapsed, 3))
        except ConnectionRefusedError:
            return ScanResult(host, port, "closed",
                              scan_time=round(time.monotonic() - t0, 3))
        except (socket.timeout, TimeoutError, OSError):
            return ScanResult(host, port, "filtered",
                              scan_time=round(time.monotonic() - t0, 3))

    # ── SYN Stealth Scan ──────────────────────────────────────────────────

    def syn_scan(self, host: str, port: int, timeout: float) -> ScanResult:
        t0 = time.monotonic()
        try:
            from scapy.all import IP, TCP, sr1, conf  # type: ignore
            conf.verb = 0

            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            elapsed = time.monotonic() - t0

            if resp is None:
                return ScanResult(host, port, "filtered",
                                  scan_time=round(elapsed, 3))

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:      # SYN-ACK → open
                    # Politely send RST to tear down the half-open connection
                    rst = IP(dst=host) / TCP(dport=port, flags="R",
                                             seq=resp[TCP].ack)
                    sr1(rst, timeout=0.5, verbose=0)
                    service = PORT_SERVICE_MAP.get(port, "")
                    return ScanResult(host, port, "open", service, "",
                                      round(elapsed, 3))
                elif flags & 0x04:     # RST → closed
                    return ScanResult(host, port, "closed",
                                      scan_time=round(elapsed, 3))

            return ScanResult(host, port, "filtered",
                              scan_time=round(elapsed, 3))

        except ImportError:
            raise RuntimeError(
                "Scapy is not installed.\n"
                "Run:  pip install scapy\n"
                "Windows also requires Npcap: https://npcap.com"
            )
        except PermissionError:
            raise RuntimeError(
                "SYN scan requires root / administrator privileges.\n"
                "• Linux:   sudo python main.py\n"
                "• Windows: Run as Administrator"
            )
        except Exception:
            return ScanResult(host, port, "filtered",
                              scan_time=round(time.monotonic() - t0, 3))

    # ── Main scan orchestration ────────────────────────────────────────────

    def run_scan(
        self,
        hosts: list[str],
        ports: list[int],
        scan_type: str,
        timeout: float,
        max_workers: int,
    ) -> None:
        scan_fn = (
            self.tcp_connect_scan if scan_type == "TCP Connect" else self.syn_scan
        )

        tasks = [(h, p) for h in hosts for p in ports]
        total = len(tasks)
        completed = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            for host, port in tasks:
                if self._stop_event.is_set():
                    break
                f = executor.submit(scan_fn, host, port, timeout)
                future_map[f] = (host, port)

            for future in as_completed(future_map):
                if self._stop_event.is_set():
                    for f in future_map:
                        f.cancel()
                    break
                host, port = future_map[future]
                try:
                    result = future.result()
                except RuntimeError as exc:
                    # Propagate critical errors (no scapy / no privileges) as a
                    # special sentinel so the GUI can surface them.
                    self._result_queue.put(("error", str(exc), 0, total))
                    return
                except Exception:
                    result = ScanResult(host, port, "filtered")

                completed += 1
                self._result_queue.put(("result", result, completed, total))

        self._result_queue.put(("done", None, completed, total))
