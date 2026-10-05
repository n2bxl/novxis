"""Console presentation for ARP-derived network state changes."""

from novxis.state import (
    ARPBinding,
    ARPBindingChanged,
    ARPBindingLearned,
    ARPBindingRefreshed,
    ARPStateChange,
)


def _format_hardware(value: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in value)


def _format_protocol(protocol_type: int, value: bytes) -> str:
    if protocol_type == 0x0800 and len(value) == 4:
        return ".".join(str(octet) for octet in value)
    return value.hex()


def _binding_text(binding: ARPBinding) -> str:
    return (
        f"interface={binding.interface} "
        f"address={_format_protocol(binding.protocol_type, binding.protocol_address)} "
        f"hardware={_format_hardware(binding.hardware_address)} "
        f"observations={binding.observation_count}"
    )


def print_arp_state_change(change: ARPStateChange) -> None:
    if isinstance(change, ARPBindingLearned):
        print(f"  ARPBindingLearned {_binding_text(change.binding)}")
        return

    if isinstance(change, ARPBindingRefreshed):
        print(f"  ARPBindingRefreshed {_binding_text(change.current)}")
        return

    if isinstance(change, ARPBindingChanged):
        print(
            "  ARPBindingChanged "
            f"interface={change.current.interface} "
            f"address={_format_protocol(change.current.protocol_type, change.current.protocol_address)} "
            f"previous_hw={_format_hardware(change.previous.hardware_address)} "
            f"current_hw={_format_hardware(change.current.hardware_address)}"
        )


def print_arp_state_snapshot(bindings: tuple[ARPBinding, ...]) -> None:
    print("ARP-derived network state")
    for binding in bindings:
        print(f"  {_binding_text(binding)}")
