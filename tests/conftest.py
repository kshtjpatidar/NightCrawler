"""
NightCrawler - Test Configuration & Strict Network Isolation
Enforces security invariant: All integration and end-to-end tests must use
mocked networking. Any unexpected live outbound network socket connection
attempted during automated tests causes immediate failure.
"""

import socket
import pytest

_real_socket_connect = socket.socket.connect


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


@pytest.fixture(autouse=True)
def enforce_test_network_isolation(monkeypatch):
    """
    Autouse fixture that blocks all unexpected outbound socket connections
    across the entire test suite.
    """
    monkeypatch.setattr(socket.socket, "connect", guarded_socket_connect)
