from __future__ import annotations

import asyncio
from typing import Optional

from .. import monitor_core as _core
from ..monitor_core import (
    DEFAULT_MAX_CHECKS,
    DEFAULT_POLL_INTERVAL,
    HttpClient,
    IPInfo,
    MonitorConfig,
    RemoteAddr,
    _read_env_float,
    _read_env_int,
    build_config,
    build_connection_report,
    extract_remote_endpoint,
    fetch_ip_infos,
    get_ip_info,
    get_ips,
    is_valid_connection,
    log_results,
    monitor_iteration,
    normalize_public_ip,
    try_exit,
    write_results,
    main as _core_main,
)

psutil = _core.psutil

__all__ = [
    "DEFAULT_MAX_CHECKS",
    "DEFAULT_POLL_INTERVAL",
    "HttpClient",
    "IPInfo",
    "MonitorConfig",
    "RemoteAddr",
    "_read_env_float",
    "_read_env_int",
    "build_config",
    "build_connection_report",
    "extract_remote_endpoint",
    "fetch_ip_infos",
    "get_ip_info",
    "get_ips",
    "is_valid_connection",
    "log_results",
    "monitor_iteration",
    "normalize_public_ip",
    "psutil",
    "try_exit",
    "write_results",
    "main",
]


async def main(config: Optional[MonitorConfig] = None) -> None:
    await _core_main(config)


if __name__ == "__main__":
    asyncio.run(main())
