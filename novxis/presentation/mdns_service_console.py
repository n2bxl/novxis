"""Display native DNS-SD identifiers rather than a fingerprint-name catalog."""

from ipaddress import ip_address

from novxis.events.mdns import MDNSMessageObserved
from novxis.presentation.ipv4_console import format_timestamp
from novxis.views.mdns_services import DNSSDServiceAdvertisement


def format_dnssd_advertisement(
    observed: MDNSMessageObserved, ad: DNSSDServiceAdvertisement
) -> str:
    """One line per observed PTR assertion; other RR claims remain traceable."""
    parts = [
        f"[{format_timestamp(observed.timestamp)}]",
        "DNSSDServiceAdvertised",
        f"interface={observed.interface}",
        f"sender={ip_address(observed.ip.source)}",
        f"service={ad.service_type.text}",
        f"instance={ad.instance.text}",
        f"ptr_ttl={ad.ptr_record.wire.ttl}s",
        f"ptr_section={ad.ptr_record.section}",
    ]
    if ad.ptr_record.goodbye_candidate:
        parts.append("goodbye-candidate")
    if not ad.targets:
        parts.append("target=not-observed-in-this-message")
    for target in ad.targets:
        addresses = ",".join(
            address.wire.decoded_data
            for address in target.address_records
            if address.wire.decoded_data is not None
        ) or "not-observed-in-this-message"
        parts.append(
            f"target={target.srv.target.text}:{target.srv.port}"
            f"(srv_ttl={target.srv_record.wire.ttl}s;"
            f"addresses={addresses})"
        )
    parts.append(f"txt_records={len(ad.txt_records)}")
    parts.append(
        "scope=same-response-evidence"
    )
    return " ".join(parts)


def print_dnssd_advertisement(
    observed: MDNSMessageObserved, ad: DNSSDServiceAdvertisement
) -> None:
    print(format_dnssd_advertisement(observed, ad))
