"""Read-only host OS network context, separate from observed packet evidence."""

from novxis.host_context.macos import collect_host_ipv4_context

__all__ = ["collect_host_ipv4_context"]
