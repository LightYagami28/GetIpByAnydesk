from __future__ import annotations

import sys
import os
import json
from dataclasses import dataclass
from pathlib import Path
import psutil
import asyncio
import aiohttp
from aiohttp import ClientTimeout
import logging
import ipaddress
from typing import Any, List, Dict, Optional, Iterable, Protocol, cast

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")


DEFAULT_POLL_INTERVAL = 5.0
DEFAULT_MAX_CHECKS = 12


IPInfo = Dict[str, str]


class RemoteAddr(Protocol):
    ip: str
    port: int


class HttpClient(Protocol):
    def get(self, url: str, /, **kwargs: Any) -> Any: ...

    async def close(self) -> Any: ...


@dataclass(slots=True)
class MonitorConfig:
    poll_interval: float = DEFAULT_POLL_INTERVAL
    max_checks: int = DEFAULT_MAX_CHECKS
    output_file: Optional[Path] = None


def is_valid_connection(conn: Any) -> bool:
    """Check if a connection is valid for logging (non-local, active AnyDesk)."""
    remote_ip, remote_port = extract_remote_endpoint(conn)
    if not remote_ip or remote_port is None:
        return False

    return (
        getattr(conn, "status", "") in ("SYN_SENT", "ESTABLISHED")
        and bool(remote_ip)
        and remote_port != 80
        and not remote_ip.startswith("192.168.")
    )


def normalize_public_ip(raw_ip: str | None) -> str | None:
    """Validate and normalize an IP address, skipping only non-routable ranges."""
    if raw_ip is None:
        return None

    try:
        parsed = ipaddress.ip_address(raw_ip)
    except ValueError:
        return None

    documentation_nets = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )

    if any(parsed in net for net in documentation_nets):
        return str(parsed)

    if parsed.is_private or parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local:
        return None

    return str(parsed)


def extract_remote_endpoint(conn: Any) -> tuple[str | None, int | None]:
    raddr = getattr(conn, "raddr", None)
    if not raddr:
        return None, None

    if isinstance(raddr, tuple):
        raddr_tuple = cast(tuple[str, int], raddr)
        remote_ip, remote_port = raddr_tuple[0], raddr_tuple[1]
    else:
        remote_ip = cast(str | None, getattr(raddr, "ip", None))
        remote_port = cast(int | None, getattr(raddr, "port", None))

    return remote_ip, remote_port


def get_ips() -> List[str]:
    """Get unique remote IPs from network connections related to AnyDesk."""
    ips: set[str] = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.Error as exc:  # pragma: no cover - defensive
        logging.error("Unable to read network connections: %s", exc)
        return []

    for conn in connections:
        if not is_valid_connection(conn):
            continue

        raddr_ip, _ = extract_remote_endpoint(conn)
        pid = conn.pid
        remote_ip = normalize_public_ip(raddr_ip)

        if not pid or not remote_ip or remote_ip in ips:
            continue

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
        except psutil.Error:
            continue

        if "anydesk" in proc_name:
            ips.add(remote_ip)

    return list(ips)


def _read_env_float(name: str, default: float, min_value: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logging.warning("Invalid value for %s='%s', using default %.2f", name, raw, default)
        return default
    if value < min_value:
        logging.warning("Value for %s below minimum %.2f, using default %.2f", name, min_value, default)
        return default
    return value


def _read_env_int(name: str, default: int, min_value: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        logging.warning("Invalid value for %s='%s', using default %d", name, raw, default)
        return default
    if value < min_value:
        logging.warning("Value for %s below minimum %d, using default %d", name, min_value, default)
        return default
    return value


def build_config() -> MonitorConfig:
    poll_interval = _read_env_float("ANYDESK_POLL_INTERVAL", DEFAULT_POLL_INTERVAL, 0.5)
    max_checks = _read_env_int("ANYDESK_MAX_CHECKS", DEFAULT_MAX_CHECKS, 1)
    output_path = os.getenv("ANYDESK_OUTPUT_FILE")
    output_file = Path(output_path) if output_path else None
    return MonitorConfig(poll_interval=poll_interval, max_checks=max_checks, output_file=output_file)


def build_connection_report(results: List[IPInfo]) -> Dict[str, List[IPInfo]]:
    return {"connections": results}


def write_results(path: Path, results: List[IPInfo]) -> None:
    if not results:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_connection_report(results)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


async def fetch_ip_infos(ips: Iterable[str], session: HttpClient | None = None) -> List[IPInfo]:
    """Fetch IP details concurrently using TaskGroup, returning results in input order."""
    ips_list = list(ips)
    if not ips_list:
        return []

    owns_session = session is None
    sess: HttpClient = session if session is not None else aiohttp.ClientSession()
    tasks: List[asyncio.Task[IPInfo]] = []

    try:
        async with asyncio.TaskGroup() as tg:  # Python 3.11+
            for ip in ips_list:
                tasks.append(tg.create_task(get_ip_info(sess, ip)))
        return [task.result() for task in tasks]
    finally:
        if owns_session:
            await sess.close()


async def get_ip_info(session: HttpClient, conn_ip: str) -> Dict[str, str]:
    """Get geographical information about the IP using the ip-api service (async)."""
    safe_ip = normalize_public_ip(conn_ip)
    if not safe_ip:
        return {
            "IP": conn_ip,
            "Country": "Unknown",
            "Region": "Unknown",
            "City": "Unknown",
            "ISP": "Unknown",
        }

    url = f"https://ip-api.com/json/{safe_ip}"
    try:
        async with session.get(url, timeout=ClientTimeout(total=5)) as response:
            data = await response.json()
            return {
                "IP": conn_ip,
                "Country": data.get("country", "Unknown"),
                "Region": data.get("regionName", "Unknown"),
                "City": data.get("city", "Unknown"),
                "ISP": data.get("isp", "Unknown"),
            }
    except aiohttp.ClientError as e:
        logging.error(f"Network error while fetching {conn_ip}: {e}")
    except asyncio.TimeoutError:
        logging.error(f"Timeout while fetching info for {conn_ip}")
    except ValueError:
        logging.error(f"Invalid JSON received for {conn_ip}")

    return {
        "IP": conn_ip,
        "Country": "Unknown",
        "Region": "Unknown",
        "City": "Unknown",
        "ISP": "Unknown",
    }


def log_results(results: Iterable[IPInfo]) -> None:
    for infos in results:
        logging.info("Connection Found, fetching details:")
        for key, value in infos.items():
            logging.info("%s: %s", key, value)


async def monitor_iteration(cfg: MonitorConfig) -> bool:
    ips = get_ips()
    logging.info(
        "Checked for connections. Found %d unique IP(s).",
        len(ips),
    )

    if not ips:
        logging.info(
            "Anydesk is turned off or no one is trying to connect to your monitor, retry... [CTRL+C to exit]"
        )
        await asyncio.sleep(cfg.poll_interval)
        return False

    results = await fetch_ip_infos(ips)
    log_results(results)

    if cfg.output_file:
        write_results(cfg.output_file, results)

    return True


def try_exit() -> None:
    """Exit from the program."""
    logging.info("Exiting program...")
    sys.exit(0)


async def main(config: Optional[MonitorConfig] = None) -> None:
    """Main loop to monitor Anydesk connections and fetch IP information asynchronously."""
    cfg = config or build_config()
    checks = 0

    while checks < cfg.max_checks:
        checks += 1
        try:
            logging.info("Attempt %d/%d", checks, cfg.max_checks)
            if await monitor_iteration(cfg):
                break

        except KeyboardInterrupt:
            logging.info("Program finished, exiting...")
            try_exit()

    else:
        logging.info("Max checks reached without detecting connections.")


if __name__ == "__main__":
    asyncio.run(main())
