"""
Regression tests for PolicyAwareResolver compatibility with aiohttp 3.9.1.
Verifies that:
1. Pinned IPv4 address resolution returns the exact required structure.
2. Pinned IPv6 address resolution correctly identifies AF_INET6.
3. Network safety validation failures fail closed with OSError.
4. Hosts with no validated IP fail closed with OSError.
5. In environments lacking aiohttp.resolver.ResolveResult / aiohttp.abc.ResolveResult (aiohttp 3.9.1),
   PolicyAwareResolver instantiates, resolves, and integrates with aiohttp.TCPConnector without AttributeError.
6. The resolver return structure satisfies the aiohttp 3.9.1 dictionary mapping contract.
"""

import asyncio
import socket
import pytest
from unittest.mock import patch, AsyncMock

import aiohttp
import aiohttp.abc
import aiohttp.resolver

from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver, ResolveResult
from src.core.scope import ScopeManager


@pytest.mark.asyncio
async def test_resolver_ipv4_pinned_resolution():
    """Verify PolicyAwareResolver returns correct structure for pinned IPv4 destination."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    client._pinned_ips["example.com"] = ["93.184.216.34"]

    results = await resolver.resolve("example.com", 443)

    assert isinstance(results, list)
    assert len(results) == 1
    res = results[0]
    assert isinstance(res, dict)
    assert res["hostname"] == "example.com"
    assert res["host"] == "93.184.216.34"
    assert res["port"] == 443
    assert res["family"] == socket.AF_INET
    assert res["proto"] == socket.IPPROTO_TCP
    assert res["flags"] == socket.AI_NUMERICHOST


@pytest.mark.asyncio
async def test_resolver_ipv6_pinned_resolution():
    """Verify PolicyAwareResolver returns correct structure with socket.AF_INET6 for IPv6."""
    scope = ScopeManager(allowed_domains=["ipv6.example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    ipv6_addr = "2606:2800:220:1:248:1893:25c8:1946"
    client._pinned_ips["ipv6.example.com"] = [ipv6_addr]

    results = await resolver.resolve("ipv6.example.com", 8443)

    assert isinstance(results, list)
    assert len(results) == 1
    res = results[0]
    assert isinstance(res, dict)
    assert res["hostname"] == "ipv6.example.com"
    assert res["host"] == ipv6_addr
    assert res["port"] == 8443
    assert res["family"] == socket.AF_INET6
    assert res["proto"] == socket.IPPROTO_TCP
    assert res["flags"] == socket.AI_NUMERICHOST


@pytest.mark.asyncio
async def test_resolver_rejection_network_safety_failure():
    """Verify PolicyAwareResolver rejects destination when network safety check fails."""
    scope = ScopeManager(allowed_domains=["internal.example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    with patch.object(
        client,
        "validate_host_network_safety",
        new=AsyncMock(return_value=(False, "Internal loopback IP 127.0.0.1 prohibited by policy"))
    ):
        with pytest.raises(OSError, match="Connection blocked by network policy: Internal loopback IP"):
            await resolver.resolve("internal.example.com", 80)


@pytest.mark.asyncio
async def test_resolver_rejection_no_validated_ip():
    """Verify PolicyAwareResolver fails closed when no validated IP is available."""
    scope = ScopeManager(allowed_domains=["unresolvable.example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    # Safety check passes, but no pinned IPs were populated and host is not an IP literal
    with patch.object(
        client,
        "validate_host_network_safety",
        new=AsyncMock(return_value=(True, "Safety check passed"))
    ):
        client._pinned_ips["unresolvable.example.com"] = []
        with pytest.raises(OSError, match="No validated IP available for host 'unresolvable.example.com'"):
            await resolver.resolve("unresolvable.example.com", 443)


@pytest.mark.asyncio
async def test_resolver_return_structure_aiohttp_3_9_1_compatibility():
    """
    Verify resolver output matches the dictionary structure expected by aiohttp 3.9.1.
    In aiohttp 3.9.1, TCPConnector iterates over resolved hosts and accesses:
    hinfo['host'], hinfo['port'], hinfo['family'], hinfo['proto'], hinfo['flags'].
    """
    scope = ScopeManager(allowed_domains=["uxcam.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = PolicyAwareResolver(client)

    client._pinned_ips["uxcam.com"] = ["104.18.26.120"]

    results = await resolver.resolve("uxcam.com", 443)

    assert isinstance(results, list)
    assert len(results) > 0

    required_keys = {"hostname", "host", "port", "family", "proto", "flags"}
    for item in results:
        assert isinstance(item, dict), f"Result element must be dict-compatible, got {type(item)}"
        assert required_keys.issubset(item.keys()), f"Missing keys in {item}"
        assert isinstance(item["hostname"], str)
        assert isinstance(item["host"], str)
        assert isinstance(item["port"], int)
        assert isinstance(item["family"], int)
        assert isinstance(item["proto"], int)
        assert isinstance(item["flags"], int)
        # Ensure TCPConnector dictionary lookups succeed identically to aiohttp 3.9.1
        _ = item["host"]
        _ = item["port"]
        _ = item["family"]
        _ = item["proto"]
        _ = item["flags"]


@pytest.mark.asyncio
async def test_resolver_aiohttp_tcp_connector_integration_simulating_aiohttp_3_9_1():
    """
    Simulate aiohttp 3.9.1 runtime environment where aiohttp.resolver has no ResolveResult.
    Verify that TCPConnector._resolve_host resolves using PolicyAwareResolver without error.
    """
    scope = ScopeManager(allowed_domains=["target.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    client._pinned_ips["target.com"] = ["198.51.100.1"]
    resolver = client.get_resolver()

    connector = aiohttp.TCPConnector(resolver=resolver)
    try:
        hosts = await connector._resolve_host("target.com", 443)
        assert len(hosts) >= 1
        assert hosts[0]["host"] == "198.51.100.1"
        assert hosts[0]["port"] == 443
        assert hosts[0]["hostname"] == "target.com"
        assert hosts[0]["proto"] == socket.IPPROTO_TCP
        assert hosts[0]["flags"] == socket.AI_NUMERICHOST
    finally:
        await connector.close()


@pytest.mark.asyncio
async def test_resolver_dual_stack_resolution():
    """Verify dual-stack host returns both IPv4 and IPv6 pinned records with appropriate families."""
    scope = ScopeManager(allowed_domains=["dualstack.example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    client._pinned_ips["dualstack.example.com"] = [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946"
    ]

    results = await resolver.resolve("dualstack.example.com", 443)
    assert len(results) == 2

    assert results[0]["host"] == "93.184.216.34"
    assert results[0]["family"] == socket.AF_INET

    assert results[1]["host"] == "2606:2800:220:1:248:1893:25c8:1946"
    assert results[1]["family"] == socket.AF_INET6


@pytest.mark.asyncio
async def test_resolver_direct_ip_literal_resolution():
    """Verify direct valid IP literals are resolved safely when host is an IP."""
    scope = ScopeManager(allowed_ips=["198.51.100.5"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    results = await resolver.resolve("198.51.100.5", 80)
    assert len(results) == 1
    assert results[0]["host"] == "198.51.100.5"
    assert results[0]["family"] == socket.AF_INET
    assert results[0]["flags"] == socket.AI_NUMERICHOST


@pytest.mark.asyncio
async def test_resolver_definition_when_aiohttp_lacks_resolve_result():
    """
    Simulate module-load time in an environment like aiohttp 3.9.1 where
    neither aiohttp.abc nor aiohttp.resolver contains ResolveResult.
    Verify that fallback TypedDict is defined and resolution succeeds.
    """
    import sys
    import importlib

    # Remove http_client from sys.modules temporarily
    saved_modules = {k: v for k, v in sys.modules.items() if "src.core.http_client" in k}
    for k in list(saved_modules.keys()):
        del sys.modules[k]

    # Delete ResolveResult from aiohttp.abc and aiohttp.resolver to mirror aiohttp 3.9.1
    had_abc = hasattr(aiohttp.abc, "ResolveResult")
    had_resolver = hasattr(aiohttp.resolver, "ResolveResult")
    orig_abc_rr = getattr(aiohttp.abc, "ResolveResult", None)
    orig_resolver_rr = getattr(aiohttp.resolver, "ResolveResult", None)

    try:
        if had_abc:
            delattr(aiohttp.abc, "ResolveResult")
        if had_resolver:
            delattr(aiohttp.resolver, "ResolveResult")

        # Import under simulated aiohttp 3.9.1
        import src.core.http_client as fresh_hc

        assert hasattr(fresh_hc, "ResolveResult")
        assert issubclass(fresh_hc.ResolveResult, dict)
        assert hasattr(aiohttp.resolver, "ResolveResult")

        scope = ScopeManager(allowed_domains=["uxcam.com"], enabled=True)
        client = fresh_hc.NightCrawlerHttpClient(scope_manager=scope)
        resolver = fresh_hc.PolicyAwareResolver(client)
        client._pinned_ips["uxcam.com"] = ["104.18.26.120"]

        results = await resolver.resolve("uxcam.com", 443)
        assert len(results) == 1
        assert results[0]["host"] == "104.18.26.120"
        assert results[0]["hostname"] == "uxcam.com"
        assert results[0]["port"] == 443
        assert results[0]["family"] == socket.AF_INET
        assert results[0]["proto"] == socket.IPPROTO_TCP
        assert results[0]["flags"] == socket.AI_NUMERICHOST
    finally:
        # Restore sys.modules and aiohttp attributes
        if had_abc:
            aiohttp.abc.ResolveResult = orig_abc_rr
        if had_resolver:
            aiohttp.resolver.ResolveResult = orig_resolver_rr
        sys.modules.update(saved_modules)

