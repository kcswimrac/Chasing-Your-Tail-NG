"""Privacy helpers."""

from cyt_platform.privacy import redact_subject, sanitize_error


def test_sanitize_strips_mac_and_paths():
    class E(Exception):
        pass

    s = sanitize_error(E("fail at /home/matt/kismet/foo AA:BB:CC:DD:EE:FF"))
    assert "AA:BB" not in s
    assert "/home/matt" not in s
    assert "<mac>" in s or "mac" in s.lower()


def test_redact_mac():
    r = redact_subject("AA:BB:CC:DD:EE:FF", "mac")
    assert r.startswith("AA:BB:")
    assert "CC:DD" not in r or "xx" in r
