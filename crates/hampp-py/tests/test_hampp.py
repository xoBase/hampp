import pytest

import hampp


def test_sign_verify_roundtrip(tmp_path):
    key = str(tmp_path / "k.json")
    pub = hampp.generate_key("agent-py", key)
    assert hampp.public_key(key) == pub
    msg = hampp.sign("Hallo aus Python", key)
    assert msg.startswith("Hallo aus Python")
    v = hampp.verify(msg, pub)
    assert v["code"] == "authenticated:signed-by-agent"
    assert v["visible"] == "Hallo aus Python"


def test_tamper_strip_and_wrong_key(tmp_path):
    key = str(tmp_path / "k.json")
    pub = hampp.generate_key("a", key)
    other = hampp.generate_key("b", str(tmp_path / "o.json"))
    msg = hampp.sign("Zahle 100", key)
    assert hampp.verify(msg.replace("100", "900"), pub)["code"] == "invalid:signature-invalid"
    assert hampp.verify(hampp.strip(msg), pub)["code"] == "unverified:envelope-missing"
    assert hampp.strip(msg) == "Zahle 100"
    assert hampp.verify(msg, other)["code"] == "unverified:unknown-key"


def test_visible_fallback_and_annotate(tmp_path):
    key = str(tmp_path / "k.json")
    pub = hampp.generate_key("a", key)
    msg = hampp.sign("Ja.", key, visible=True)
    assert "[hampp1:" in msg
    assert hampp.verify(msg, pub)["status"] == "authenticated"
    out = hampp.annotate(hampp.sign("Hallo", key), pub)
    assert out.startswith("[HAMPP:v1 AUTHENTICATED signed-by-agent")


def test_generate_key_refuses_overwrite(tmp_path):
    key = str(tmp_path / "k.json")
    hampp.generate_key("a", key)
    with pytest.raises(ValueError):
        hampp.generate_key("a", key)


def test_bad_public_key_is_a_value_error():
    with pytest.raises(ValueError):
        hampp.verify("x", "nothex")
