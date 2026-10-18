"""Terminal-only DNS label formatting; never reinterpret original bytes."""

from novxis.presentation.dns_names import format_dns_name_display
from novxis.protocols.dns import DNSName


def test_space_bytes_are_readable_and_name_remains_unchanged():
    name = DNSName((b"Test Desk Mac", b"_companion-link", b"_tcp", b"local"))
    assert name.text == r"Test\x20Desk\x20Mac._companion-link._tcp.local"
    assert format_dns_name_display(name) == (
        '"Test Desk Mac._companion-link._tcp.local"'
    )
    assert name.labels[0] == b"Test Desk Mac"
    assert name.text == r"Test\x20Desk\x20Mac._companion-link._tcp.local"


def test_native_protocol_service_type_is_not_replaced_or_quoted():
    service = DNSName((b"_spotify-connect", b"_tcp", b"local"))
    assert format_dns_name_display(service) == "_spotify-connect._tcp.local"


def test_embedded_dot_and_backslash_remain_escaped_label_bytes():
    name = DNSName((b"Studio.Room\\East", b"_example", b"_tcp", b"local"))
    assert format_dns_name_display(name) == (
        r"Studio\x2eRoom\x5cEast._example._tcp.local"
    )


def test_injection_unprintable_non_ascii_and_quotes_stay_escaped():
    name = DNSName((b"n\t\r\n\x00\xff\"x", b"local"))
    assert format_dns_name_display(name) == (
        r"n\x09\x0d\x0a\x00\xff\x22x.local"
    )


def test_root_name_is_rendered_as_dot():
    assert format_dns_name_display(DNSName(())) == "."
