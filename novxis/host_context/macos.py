"""Conservative, read-only macOS IPv4 interface and default-route context.

This module never changes network configuration, infers device identities or
assumes the default route is through the interface being captured.
It is used only by the unprivileged local web process.
"""

import ipaddress
import re
import subprocess
import sys
from datetime import datetime, timezone


_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
_INET = re.compile(r"^\s*inet\s+(\S+)\s+netmask\s+(\S+)", re.MULTILINE)
_ROUTE_FIELD = re.compile(r"^\s*([a-z ]+):\s*(.*?)\s*$", re.MULTILINE)


def valid_interface_name(name: str) -> bool:
    """Reject options, whitespace, shell-like input and unknown long names."""
    return isinstance(name, str) and _INTERFACE.fullmatch(name) is not None


def parse_macos_ifconfig_ipv4(output: str) -> tuple[dict, ...]:
    """Parse macOS ifconfig 'inet ADDRESS netmask 0x...' observations.

    A configured address and the derived connected prefix are **host
    configuration facts**, not ARP observations or discovered hosts.
    """
    result = []
    seen = set()
    for match in _INET.finditer(output):
        address, mask = match.groups()
        try:
            if mask.lower().startswith("0x"):
                value = int(mask, 16)
                if not 0 <= value <= 0xFFFFFFFF:
                    continue
                mask = str(ipaddress.IPv4Address(value))
            configured = ipaddress.IPv4Interface(f"{address}/{mask}")
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
        fact = (
            str(configured.ip),
            configured.network.prefixlen,
            str(configured.network),
        )
        if fact not in seen:
            result.append({
                "address": fact[0],
                "prefix_length": fact[1],
                "network": fact[2],
            })
            seen.add(fact)
        if len(result) >= 16:
            break
    return tuple(result)


def parse_macos_default_route(output: str) -> dict | None:
    """Read a single macOS 'route -n get default' result, if valid.

    This describes the OS-selected IPv4 default route at query time, which
    need not use the selected capture interface.
    """
    fields = {key.strip(): value.strip()
              for key, value in _ROUTE_FIELD.findall(output)}
    if fields.get("destination") != "default":
        return None
    interface = fields.get("interface")
    if not valid_interface_name(interface):
        return None
    try:
        gateway = str(ipaddress.IPv4Address(fields.get("gateway", "")))
    except ValueError:
        return None
    return {
        "gateway": gateway,
        "interface": interface,
        "scope": "os-selected-ipv4-default",
    }


def collect_host_ipv4_context(
    interface: str, *, runner=subprocess.run, platform_name: str | None = None,
) -> dict:
    """Take one unprivileged host-configuration snapshot for the live viewer.

    Never passes a shell command or returns raw command output. Parsing and
    subprocess errors become visible 'unavailable' statuses, not invented
    gateway or subnet facts.
    """
    platform_name = sys.platform if platform_name is None else platform_name
    snapshot = {
        "schema_version": 1,
        "origin": "local-os",
        "platform": "macos" if platform_name == "darwin" else "unsupported",
        "interface": interface if valid_interface_name(interface) else None,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "status": "unavailable",
        "interface_status": "unavailable",
        "route_status": "unavailable",
        "ipv4_addresses": [],
        "default_route": None,
    }
    if platform_name != "darwin":
        snapshot["status"] = "unsupported"
        return snapshot
    if not valid_interface_name(interface):
        return snapshot

    def call(args):
        try:
            completed = runner(
                args, capture_output=True, text=True, check=False, timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if completed.returncode != 0:
            return None
        return completed.stdout[:131072]

    ifconfig_output = call(["/sbin/ifconfig", interface])
    if ifconfig_output is not None:
        snapshot["interface_status"] = "reported"
        snapshot["ipv4_addresses"] = list(parse_macos_ifconfig_ipv4(ifconfig_output))
    route_output = call(["/sbin/route", "-n", "get", "default"])
    if route_output is not None:
        default_route = parse_macos_default_route(route_output)
        if default_route is not None:
            snapshot["default_route"] = default_route
            snapshot["route_status"] = "reported"

    if snapshot["interface_status"] == "reported" and (
        snapshot["route_status"] == "reported"
    ):
        snapshot["status"] = "reported"
    elif (snapshot["interface_status"] == "reported"
          or snapshot["route_status"] == "reported"):
        snapshot["status"] = "partial"
    return snapshot
