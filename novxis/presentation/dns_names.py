"""Readable, unambiguous terminal rendering of DNS label bytes.

Protocol DNSName.text intentionally uses escaped syntax for bytes that
cannot be displayed safely. This module changes *only* terminal output;
it never alters DNSName.labels, evidence keys or parser behavior.
"""

from novxis.protocols.dns import DNSName


def format_dns_name_display(name: DNSName) -> str:
    """Render ASCII spaces naturally; escape separators and unsafe bytes.

    DNS label boundaries are encoded by literal dots; a dot *inside*
    a label remains \x2e. Backslashes, double quotes, control bytes
    and bytes outside printable ASCII remain \xNN so quoted fields cannot
    inject newline text or appear to contain extra key/value fields.
    Values with ASCII spaces are double-quoted to keep key/value fields
    unambiguous. This is a display string, not a wire-format serializer.
    """
    if not name.labels:
        rendered = "."
    else:
        rendered = ".".join(
            "".join(
                chr(byte) if 32 <= byte <= 126 and byte not in (34, 46, 92)
                else f"\\x{byte:02x}"
                for byte in label
            )
            for label in name.labels
        )
    return f'"{rendered}"' if any(b" " in label for label in name.labels) else rendered
