"""Stage 2: consistent DNS-SD and NDP metadata presentation contracts.

Source-level assertions only. Local Safari acceptance still required.
"""
from importlib import resources


def assets():
    root = resources.files("novxis.web.static")
    return (
        root.joinpath("app.js").read_text(encoding="utf-8"),
        root.joinpath("styles.css").read_text(encoding="utf-8"),
    )


def test_metadata_fields_get_separate_text_only_elements():
    js, css = assets()
    helper = js[js.index("function appendEvidenceMetadata("):
                js.index("function showNDPEvidence(")]
    assert 'String(detail).split(" · ")' in helper
    assert 'document.createElement("p")' in helper
    assert '"evidence-metadata-line"' in helper
    assert 'line.textContent = (index === 0 ? "" : "· ") + value;' in helper
    assert "parent.append(line);" in helper
    assert "innerHTML" not in helper
    assert ".evidence-metadata-line {" in css
    assert "overflow-wrap: anywhere;" in css


def test_dns_sd_metadata_has_per_claim_fields_and_existing_navigation():
    js, _ = assets()
    view = js[js.index("function showMDNSEvidence("):
              js.index("function clearInspector(")]
    for expected in (
        'appendEvidenceMetadata(record, type.textContent);',
        'appendEvidenceMetadata(record, detail.textContent);',
        'appendEvidenceMetadata(claim, label.textContent);',
        'appendEvidenceMetadata(line, summary.textContent);',
        'target.path_fresh ? " · PTR+SRV fresh"',
        'address.path_fresh ? " · chain fresh"',
        'target.source === "cross-mdns-response"',
        'address.source === "cross-mdns-response"',
        'button.textContent = "Inspect independent ARP address";',
        'button.textContent = "Inspect independent IPv6 neighbor evidence";',
    ):
        assert expected in view
    assert "innerHTML" not in view


def test_ipv6_neighbor_claims_remain_separate_with_all_provenance():
    js, _ = assets()
    view = js[js.index("function showNDPEvidence("):
              js.index("function showMDNSEvidence(")]
    assert view.count("appendEvidenceMetadata(record, detail.textContent);") == 2
    for expected in (
        '"NS source SLLA claim"',
        '"NA target TLLA claim"',
        '" · advertised Ethernet "',
        '" · captured "',
        '" (not a target-MAC association)"',
        '"No NDP freshness TTL is inferred."',
    ):
        assert expected in view
    assert "innerHTML" not in view
