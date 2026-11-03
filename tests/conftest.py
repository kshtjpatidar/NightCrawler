"""
NightCrawler - Test Configuration & Strict Network Isolation
Enforces security invariant: All integration and end-to-end tests must use
mocked networking. Any unexpected live outbound network socket connection
attempted during automated tests causes immediate failure.
"""

import socket
import ipaddress
import pytest

_real_socket_connect = socket.socket.connect
_real_getaddrinfo = socket.getaddrinfo


def guarded_socket_connect(self, address):
    # Allow Unix domain sockets if address is a path string
    if isinstance(address, str):
        return _real_socket_connect(self, address)

    host = address[0] if isinstance(address, (tuple, list)) and len(address) > 0 else str(address)
    port = address[1] if isinstance(address, (tuple, list)) and len(address) > 1 else 0

    # In strict test isolation, unexpected real network connections cause immediate test failure
    raise RuntimeError(
        f"TEST SECURITY VIOLATION: Unexpected real network connection attempted to {host}:{port}! "
        f"All automated tests must use mocked networking and transports."
    )


def mock_test_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """
    Mock DNS resolution in offline test environment.
    Resolves domain names to safe public documentation IP (93.184.216.34)
    unless explicitly testing localhost, IP targets, or overridden by test patches.
    """
    if not host:
        return []
    try:
        ip = ipaddress.ip_address(host)
        fam = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 6, '', (str(ip), port or 0))]
    except ValueError:
        pass

    if host in ("localhost", "127.0.0.1"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port or 0))]

    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 0))]


@pytest.fixture(autouse=True)
def enforce_test_network_isolation(monkeypatch):
    """
    Autouse fixture that blocks all unexpected outbound socket connections
    and provides mock DNS resolution across the test suite.
    """
    monkeypatch.setattr(socket.socket, "connect", guarded_socket_connect)
    monkeypatch.setattr(socket, "getaddrinfo", mock_test_getaddrinfo)
