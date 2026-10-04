from novxis.capture import interfaces


def test_list_interfaces_preserves_scapy_order(monkeypatch):
    monkeypatch.setattr(
        interfaces,
        "get_if_list",
        lambda: ["lo0", "en0", "bridge0"],
    )

    assert interfaces.list_interfaces() == ("lo0", "en0", "bridge0")


def test_list_interfaces_can_return_empty_tuple(monkeypatch):
    monkeypatch.setattr(interfaces, "get_if_list", lambda: [])

    assert interfaces.list_interfaces() == ()
