"""Shared link-layer constraints for NOVXIS protocol pipelines."""

DLT_EN10MB = 1


class UnsupportedLinkTypeError(ValueError):
    """Raised when a protocol pipeline receives a known non-Ethernet link type."""


def validate_ethernet_link_type(link_type: int | None) -> None:
    """Accept Ethernet captures and live frames whose link type is unknown."""
    if link_type in (None, DLT_EN10MB):
        return

    raise UnsupportedLinkTypeError(
        f"NOVXIS protocol pipelines support Ethernet link type {DLT_EN10MB}; "
        f"got {link_type}."
    )
