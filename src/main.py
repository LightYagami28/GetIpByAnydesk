import os
import sys
import wmi
import psutil
import requests
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def get_ips() -> List[str]:
    """Get unique IPs of remote connections from Anydesk processes."""
    wmi_obj = wmi.WMI()
    ips = []

    for process in wmi_obj.Win32_Process():
        try:
            if 'anydesk' in process.Name.lower():
                for conn in psutil.Process(process.ProcessId).connections():
                    if conn.status in ('SYN_SENT', 'ESTABLISHED') and conn.raddr.ip:
                        conn_ip = conn.raddr.ip
                        if conn.raddr.port != 80 and not conn_ip.startswith('192.168.') and conn_ip not in ips:
                            ips.append(conn_ip)
        except psutil.NoSuchProcess:
            continue

    return ips

def get_ip_info(conn_ip: str) -> Dict[str, str]:
    """Get geographical information about the IP using the ip-api service."""
    try:
        response = requests.get(f'http://ip-api.com/json/{conn_ip}', timeout=5)
        response.raise_for_status() 
        data = response.json()
        return {
            "IP": conn_ip,
            "Country": data.get('country', 'Unknown'),
            "Region": data.get('regionName', 'Unknown'),
            "City": data.get('city', 'Unknown'),
            "ISP": data.get('isp', 'Unknown')
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get IP info for {conn_ip}: {e}")
        return {
            "IP": conn_ip,
            "Country": "Unknown",
            "Region": "Unknown",
            "City": "Unknown",
            "ISP": "Unknown"
        }

def try_exit() -> None:
    """Exit from the program."""
    logging.info("Exiting program...")
    sys.exit(0)

def main() -> None:
    """Main loop to monitor Anydesk connections and fetch IP information."""
    msg = 'Anydesk is turned off or no one is trying to connect to your monitor, retry... [CTRL+C to exit]'

    while True:
        try:
            ips = get_ips()
            logging.info(f"Checked for connections. Found {len(ips)} unique IP(s).")

            if ips:
                for conn_ip in ips:
                    logging.info("Connection Found, fetching details:")
                    infos = get_ip_info(conn_ip)
                    for key, value in infos.items():
                        logging.info(f'{key}: {value}')
            else:
                logging.info(msg)
        except KeyboardInterrupt:
            logging.info('Program finished, exiting...')
            try_exit()

        if ips:
            break

if __name__ == '__main__':
    main()
