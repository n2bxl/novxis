"""Read-only data projections for terminal and future cyberspace renderers."""

from novxis.views.dns_relationships import (
    DNSRelationshipSnapshot,
    DNSRelationshipView,
    project_dns_relationships,
)

__all__ = [
    "DNSRelationshipSnapshot",
    "DNSRelationshipView",
    "project_dns_relationships",
]
