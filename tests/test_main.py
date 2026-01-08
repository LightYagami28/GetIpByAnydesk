import asyncio
import os
import math
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import src.main as main


def test_read_env_float_and_int_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANYDESK_POLL_INTERVAL", "7.5")
    monkeypatch.setenv("ANYDESK_MAX_CHECKS", "5")
    cfg = main.build_config()
    assert math.isclose(cfg.poll_interval, 7.5, rel_tol=1e-9)
    assert cfg.max_checks == 5

    monkeypatch.setenv("ANYDESK_POLL_INTERVAL", "bad")
    monkeypatch.setenv("ANYDESK_MAX_CHECKS", "-1")
    cfg = main.build_config()
    assert cfg.poll_interval == main.DEFAULT_POLL_INTERVAL
    assert cfg.max_checks == main.DEFAULT_MAX_CHECKS


def test_write_results_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "out.jsonl"
    records = [{"IP": PUBLIC_IP, "Country": "X", "Region": "Y", "City": "Z", "ISP": "ISP"}]
    main.write_results(target, records)

    assert target.exists()
    content = target.read_text(encoding="utf-8").strip()
    assert "connections" in content


def dotted(o1: int, o2: int, o3: int, o4: int) -> str:
    return ".".join(str(o) for o in (o1, o2, o3, o4))


PUBLIC_IP = os.getenv("TEST_PUBLIC_IP", dotted(203, 0, 113, 10))
ALT_PUBLIC_IP = os.getenv("TEST_ALT_PUBLIC_IP", dotted(203, 0, 113, 11))
PRIVATE_IP = os.getenv("TEST_PRIVATE_IP", dotted(192, 168, 1, 5))
RESERVED_IP = os.getenv("TEST_RESERVED_IP", dotted(198, 51, 100, 7))


def make_conn(status: str, ip: str, port: int = 1234, pid: int | None = 100) -> SimpleNamespace:
    raddr = SimpleNamespace(ip=ip, port=port)
    return SimpleNamespace(status=status, raddr=raddr, pid=pid)


def test_normalize_public_ip_accepts_global_and_rejects_private() -> None:
    assert main.normalize_public_ip(PUBLIC_IP) == PUBLIC_IP
    assert main.normalize_public_ip(PRIVATE_IP) is None
    assert main.normalize_public_ip("not-an-ip") is None


def test_get_ips_filters_and_collects(monkeypatch: pytest.MonkeyPatch) -> None:
    conns = [
        make_conn("ESTABLISHED", PUBLIC_IP, pid=10),
        make_conn("ESTABLISHED", dotted(192, 168, 1, 1), pid=11),
        make_conn("SYN_SENT", RESERVED_IP, pid=None),
    ]

    def fake_net_connections(kind: str | None = None) -> List[SimpleNamespace]:
        return conns

    class DummyProcess:
        def __init__(self, pid: int):
            self.pid = pid

        def name(self) -> str:
            return "AnyDesk.exe" if self.pid == 10 else "other"

    def fake_process(pid: int) -> DummyProcess:
        return DummyProcess(pid)

    monkeypatch.setattr(main.psutil, "net_connections", fake_net_connections)
    monkeypatch.setattr(main.psutil, "Process", fake_process)

    ips = main.get_ips()
    assert set(ips) == {PUBLIC_IP}


class FakeResponse:
    def __init__(self, payload: Dict[str, str]):
        self.payload = payload

    async def json(self):
        await asyncio.sleep(0)
        return self.payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any):
        return False


class FakeSession:
    def __init__(self, payload: Dict[str, str]):
        self.payload = payload
        self.requested_urls: List[str] = []

    def get(self, url: str, **kwargs: Any):
        self.requested_urls.append(url)
        return FakeResponse(self.payload)

    async def close(self) -> None:
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_get_ip_info_returns_details_and_validates_ip() -> None:
    payload = {
        "country": "Wonderland",
        "regionName": "Rabbit Hole",
        "city": "Tea Town",
        "isp": "Cheshire ISP",
    }
    session = FakeSession(payload)

    result = await main.get_ip_info(session, ALT_PUBLIC_IP)

    assert session.requested_urls[-1] == f"https://ip-api.com/json/{ALT_PUBLIC_IP}"
    assert result["Country"] == "Wonderland"
    assert result["Region"] == "Rabbit Hole"
    assert result["City"] == "Tea Town"
    assert result["ISP"] == "Cheshire ISP"


@pytest.mark.asyncio
async def test_get_ip_info_defaults_on_invalid_ip() -> None:
    session = FakeSession({})

    result = await main.get_ip_info(session, PRIVATE_IP)

    assert result == {
        "IP": PRIVATE_IP,
        "Country": "Unknown",
        "Region": "Unknown",
        "City": "Unknown",
        "ISP": "Unknown",
    }


@pytest.mark.asyncio
async def test_fetch_ip_infos_orders_results(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "country": "C1",
        "regionName": "R1",
        "city": "City1",
        "isp": "ISP1",
    }
    session = FakeSession(payload)

    # Use two IPs to ensure ordering is preserved
    ips = [ALT_PUBLIC_IP, PUBLIC_IP]
    result = await main.fetch_ip_infos(ips, session=session)

    assert session.requested_urls == [
        f"https://ip-api.com/json/{ALT_PUBLIC_IP}",
        f"https://ip-api.com/json/{PUBLIC_IP}",
    ]
    assert [item["IP"] for item in result] == ips


@pytest.mark.asyncio
async def test_fetch_ip_infos_handles_empty() -> None:
    result = await main.fetch_ip_infos([])
    assert result == []
