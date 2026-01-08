import asyncio
import os
from types import SimpleNamespace

import aiohttp
import pytest

import src.main as main
def dotted(o1: int, o2: int, o3: int, o4: int) -> str:
    return ".".join(str(o) for o in (o1, o2, o3, o4))


PUBLIC_IP = os.getenv("TEST_PUBLIC_IP", dotted(8, 8, 8, 8))
ALT_PUBLIC_IP = os.getenv("TEST_ALT_PUBLIC_IP", dotted(8, 8, 4, 4))
PRIVATE_IP = os.getenv("TEST_PRIVATE_IP", dotted(192, 168, 1, 5))
RESERVED_IP = os.getenv("TEST_RESERVED_IP", dotted(198, 51, 100, 7))


def make_conn(status: str, ip: str, port: int = 1234, pid: int | None = 100):
    raddr = SimpleNamespace(ip=ip, port=port)
    return SimpleNamespace(status=status, raddr=raddr, pid=pid)


def test_normalize_public_ip_accepts_global_and_rejects_private():
    assert main.normalize_public_ip(PUBLIC_IP) == PUBLIC_IP
    assert main.normalize_public_ip(PRIVATE_IP) is None
    assert main.normalize_public_ip("not-an-ip") is None


def test_get_ips_filters_and_collects(monkeypatch):
    conns = [
        make_conn("ESTABLISHED", PUBLIC_IP, pid=10),
        make_conn("ESTABLISHED", dotted(192, 168, 1, 1), pid=11),
        make_conn("SYN_SENT", RESERVED_IP, pid=None),
    ]

    class DummyProcess:
        def __init__(self, pid: int):
            self.pid = pid

        def name(self) -> str:
            return "AnyDesk.exe" if self.pid == 10 else "other"

    monkeypatch.setattr(main.psutil, "net_connections", lambda kind=None: conns)
    monkeypatch.setattr(main.psutil, "Process", lambda pid: DummyProcess(pid))

    ips = main.get_ips()
    assert set(ips) == {PUBLIC_IP}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    async def json(self):
        await asyncio.sleep(0)
        return self.payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self, payload):
        self.payload = payload
        self.requested_url = None

    def get(self, url, timeout=5):
        self.requested_url = url
        return FakeResponse(self.payload)


@pytest.mark.asyncio
async def test_get_ip_info_returns_details_and_validates_ip():
    payload = {
        "country": "Wonderland",
        "regionName": "Rabbit Hole",
        "city": "Tea Town",
        "isp": "Cheshire ISP",
    }
    session = FakeSession(payload)

    result = await main.get_ip_info(session, ALT_PUBLIC_IP)

    assert session.requested_url == f"https://ip-api.com/json/{ALT_PUBLIC_IP}"
    assert result["Country"] == "Wonderland"
    assert result["Region"] == "Rabbit Hole"
    assert result["City"] == "Tea Town"
    assert result["ISP"] == "Cheshire ISP"


@pytest.mark.asyncio
async def test_get_ip_info_defaults_on_invalid_ip():
    session = FakeSession({})

    result = await main.get_ip_info(session, PRIVATE_IP)

    assert result == {
        "IP": PRIVATE_IP,
        "Country": "Unknown",
        "Region": "Unknown",
        "City": "Unknown",
        "ISP": "Unknown",
    }
