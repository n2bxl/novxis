"""Read-only macOS host configuration parsing and command isolation."""

from types import SimpleNamespace

import pytest

from novxis.host_context.macos import (
    collect_host_ipv4_context,
    parse_macos_default_route,
    parse_macos_ifconfig_ipv4,
    valid_interface_name,
)

IFCONFIG = """en5: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
    ether 02:00:00:00:00:01
    inet6 fe80::aede:48ff:fe00:1122%en5 prefixlen 64
    inet 192.0.2.34 netmask 0xffffff00 broadcast 192.0.2.255
    inet 198.51.100.25 netmask 255.255.255.240 broadcast 198.51.100.31
    status: active
"""
DEFAULT_ROUTE = """   route to: default
destination: default
       mask: default
    gateway: 198.51.100.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
"""


def test_hex_and_dotted_netmasks_produce_reported_prefixes():
    assert parse_macos_ifconfig_ipv4(IFCONFIG) == (
        {"address": "192.0.2.34", "prefix_length": 24,
         "network": "192.0.2.0/24"},
        {"address": "198.51.100.25", "prefix_length": 28,
         "network": "198.51.100.16/28"},
    )


def test_invalid_addresses_or_non_contiguous_masks_fail_closed():
    output = """inet 999.2.3.4 netmask 0xffffff00
    inet 192.0.2.1 netmask 0xff00ff00
    inet 192.0.2.2 netmask nonsense
    inet 192.0.2.3 netmask 0x100000000
    """
    assert parse_macos_ifconfig_ipv4(output) == ()


def test_duplicate_address_config_is_not_returned_twice():
    output = """inet 192.0.2.34 netmask 0xffffff00
    inet 192.0.2.34 netmask 0xffffff00"""
    assert len(parse_macos_ifconfig_ipv4(output)) == 1


def test_default_route_has_actual_reported_gateway_and_interface():
    assert parse_macos_default_route(DEFAULT_ROUTE) == {
        "gateway": "198.51.100.1",
        "interface": "en0",
        "scope": "os-selected-ipv4-default",
    }


@pytest.mark.parametrize("text", [
    "destination: default\\ngateway: link#4\\ninterface: en5",
    "destination: default\\ngateway: 192.0.2.1\\ninterface: -help",
    "destination: 203.0.113.1\\ngateway: 192.0.2.1\\ninterface: en5",
    "destination: default\\ngateway: 999.1.1.1\\ninterface: en5",
    "destination: default\\ngateway: 192.0.2.1",
])
def test_invalid_route_cannot_become_gateway(text):
    assert parse_macos_default_route(text) is None


@pytest.mark.parametrize("name", ["en5", "en0", "bridge0", "utun7", "vlan.3"])
def test_valid_interface_names(name):
    assert valid_interface_name(name)


@pytest.mark.parametrize("name", ["-a", "", "../en5", "en 5", "en5;whoami", "a"*33, None])
def test_rejects_interface_argument_injection(name):
    assert not valid_interface_name(name)


def test_collector_runs_only_read_only_absolute_path_commands():
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "/sbin/ifconfig":
            return SimpleNamespace(returncode=0, stdout=IFCONFIG)
        return SimpleNamespace(returncode=0, stdout=DEFAULT_ROUTE)

    result = collect_host_ipv4_context(
        "en5", runner=fake_run, platform_name="darwin",
    )
    assert [args for args, _ in calls] == [
        ["/sbin/ifconfig", "en5"],
        ["/sbin/route", "-n", "get", "default"],
    ]
    for _, kwargs in calls:
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == 3
        assert kwargs["text"] is True
    assert result["status"] == "reported"
    assert result["origin"] == "local-os"
    assert result["ipv4_addresses"][0]["network"] == "192.0.2.0/24"
    assert result["default_route"]["interface"] == "en0"
    assert result["default_route"]["gateway"] == "198.51.100.1"


def test_no_route_does_not_invent_gateway_or_local_connectivity():
    def fake_run(argv, **kwargs):
        if argv[0] == "/sbin/ifconfig":
            return SimpleNamespace(returncode=0, stdout=IFCONFIG)
        return SimpleNamespace(returncode=1, stdout="")

    result = collect_host_ipv4_context(
        "en5", runner=fake_run, platform_name="darwin",
    )
    assert result["status"] == "partial"
    assert result["default_route"] is None
    assert result["route_status"] == "unavailable"
    assert result["interface_status"] == "reported"


def test_no_ipv4_address_is_not_converted_to_a_fabricated_prefix():
    def fake_run(argv, **kwargs):
        if argv[0] == "/sbin/ifconfig":
            return SimpleNamespace(returncode=0, stdout="en5: flags=0\\n")
        return SimpleNamespace(returncode=0, stdout=DEFAULT_ROUTE)

    result = collect_host_ipv4_context(
        "en5", runner=fake_run, platform_name="darwin",
    )
    assert result["ipv4_addresses"] == []
    assert result["default_route"]["interface"] == "en0"


def test_unsupported_platform_and_invalid_argument_run_no_commands():
    def no_call(*args, **kwargs):
        raise AssertionError("should not execute OS commands")

    unsupported = collect_host_ipv4_context(
        "en5", runner=no_call, platform_name="linux",
    )
    invalid = collect_host_ipv4_context(
        "--help", runner=no_call, platform_name="darwin",
    )
    assert unsupported["status"] == "unsupported"
    assert invalid["status"] == "unavailable"
    assert unsupported["ipv4_addresses"] == []
    assert invalid["default_route"] is None


def test_subprocess_exception_is_safe_and_non_fatal():
    def raises(*args, **kwargs):
        raise OSError("secret command path and private network information")
    result = collect_host_ipv4_context(
        "en5", runner=raises, platform_name="darwin",
    )
    assert result["status"] == "unavailable"
    assert "secret" not in str(result)
