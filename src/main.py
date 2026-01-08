import sys
import psutil
import asyncio
import aiohttp
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")


def is_valid_connection(conn: psutil._common.sconn) -> bool:
    """Check if a connection is valid for logging (non-local, active AnyDesk)."""
    return (
        conn.status in ("SYN_SENT", "ESTABLISHED")
        and conn.raddr
        and conn.raddr.ip
        and conn.raddr.port != 80
        and not conn.raddr.ip.startswith("192.168.")
    )


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

        pid = conn.pid
        remote_ip = getattr(conn.raddr, "ip", None)

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


async def get_ip_info(session: aiohttp.ClientSession, conn_ip: str) -> Dict[str, str]:
    """Get geographical information about the IP using the ip-api service (async)."""
    url = f"https://ip-api.com/json/{conn_ip}"
    try:
        async with session.get(url, timeout=5) as response:
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


def try_exit() -> None:
    """Exit from the program."""
    logging.info("Exiting program...")
    sys.exit(0)


async def main() -> None:
    """Main loop to monitor Anydesk connections and fetch IP information asynchronously."""
    msg = "Anydesk is turned off or no one is trying to connect to your monitor, retry... [CTRL+C to exit]"

    while True:
        ips: List[str] = []  # sempre inizializzato
        try:
            ips = get_ips()
            logging.info(f"Checked for connections. Found {len(ips)} unique IP(s).")

            if ips:
                async with aiohttp.ClientSession() as session:
                    tasks = [get_ip_info(session, ip) for ip in ips]
                    results = await asyncio.gather(*tasks)

                for infos in results:
                    logging.info("Connection Found, fetching details:")
                    for key, value in infos.items():
                        logging.info(f"{key}: {value}")
            else:
                logging.info(msg)

        except KeyboardInterrupt:
            logging.info("Program finished, exiting...")
            try_exit()

        if ips:
            break


if __name__ == "__main__":
    asyncio.run(main())
