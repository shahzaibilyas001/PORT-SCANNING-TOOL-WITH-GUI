import ipaddress
import os
import socket
import sys


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 27017,
]


def get_common_ports() -> list[int]:
    return list(COMMON_PORTS)


def validate_and_expand_target(target: str) -> list[str]:
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    # Try CIDR notation first
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in network.hosts()]
            # /32 or /128 has no "hosts" — return the network address itself
            if not hosts:
                hosts = [str(network.network_address)]
            return hosts
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: '{target}'")

    # Try plain IP address
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    # Try hostname resolution
    try:
        resolved = socket.gethostbyname(target)
        return [resolved]
    except socket.gaierror:
        raise ValueError(
            f"Cannot resolve hostname '{target}'.\n"
            "Check the spelling and your network connection."
        )


def parse_ports(port_input: str) -> list[int]:
    port_input = port_input.strip().lower()
    if not port_input:
        raise ValueError("Port field cannot be empty.")

    if port_input in ("common", "top", "top ports"):
        return get_common_ports()

    ports: set[int] = set()

    for part in port_input.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo = int(bounds[0].strip())
                hi = int(bounds[1].strip())
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'")
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(
                    f"Port range '{part}' is out of bounds. Valid range: 1–65535."
                )
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port value: '{part}'")
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} is out of range. Valid: 1–65535.")
            ports.add(p)

    if not ports:
        raise ValueError("No valid ports found in the input.")

    return sorted(ports)


def check_privileges() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0
