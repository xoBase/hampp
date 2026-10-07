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


# ---- ECDSA P-256 (suite 2) and protection levels ----


def test_p256_sign_verify_roundtrip(tmp_path):
    key = str(tmp_path / "p.json")
    pub = hampp.generate_key("agent-p256", key, alg="ecdsa-p256")
    assert len(pub) == 66  # 33-byte compressed point
    assert hampp.public_key(key) == pub
    msg = hampp.sign("Hallo mit P-256", key)
    v = hampp.verify(msg, pub)
    assert v["code"] == "authenticated:signed-by-agent"
    assert v["visible"] == "Hallo mit P-256"
    assert v["protection"] == "software"
    assert hampp.sign("Ja.", key, visible=True).count("[hampp1:") == 1


def test_p256_tamper_strip_and_cross_type(tmp_path):
    pk = str(tmp_path / "p.json")
    ek = str(tmp_path / "e.json")
    ppub = hampp.generate_key("p", pk, alg="ecdsa-p256")
    epub = hampp.generate_key("e", ek)  # default stays Ed25519
    assert len(epub) == 64
    msg = hampp.sign("Zahle 100", pk)
    assert hampp.verify(msg.replace("100", "900"), ppub)["code"] == "invalid:signature-invalid"
    assert hampp.verify(hampp.strip(msg), ppub)["code"] == "unverified:envelope-missing"
    # a key of the other type never verifies it
    assert hampp.verify(msg, epub)["code"] == "unverified:unknown-key"
    assert hampp.verify(hampp.sign("x", ek), ppub)["code"] == "unverified:unknown-key"


def test_p256_annotate(tmp_path):
    key = str(tmp_path / "p.json")
    pub = hampp.generate_key("p", key, alg="ecdsa-p256")
    out = hampp.annotate(hampp.sign("Hallo", key), pub)
    assert out.startswith("[HAMPP:v1 AUTHENTICATED signed-by-agent")


def test_protection_claim_and_receiver_policy(tmp_path):
    key = str(tmp_path / "p.json")
    pub = hampp.generate_key("p", key, alg="ecdsa-p256")
    # the honest claim works; a software key can never claim bound (no silent fallback)
    msg = hampp.sign("Routine", key, protection="software")
    assert hampp.verify(msg, pub)["protection"] == "software"
    with pytest.raises(ValueError, match="not available"):
        hampp.sign("Wichtig", key, protection="bound")
    # a receiver can require a minimum
    low = hampp.verify(msg, pub, min_protection="bound")
    assert low["code"] == "unverified:protection-too-low"
    assert hampp.verify(msg, pub, min_protection="software")["status"] == "authenticated"


def test_ed25519_keys_offer_software_only(tmp_path):
    key = str(tmp_path / "e.json")
    hampp.generate_key("e", key)
    with pytest.raises(ValueError):
        hampp.sign("x", key, protection="bound")


def test_bad_arguments_are_value_errors(tmp_path):
    key = str(tmp_path / "k.json")
    with pytest.raises(ValueError, match="unknown key algorithm"):
        hampp.generate_key("a", key, alg="rsa")
    assert not (tmp_path / "k.json").exists()
    pub = hampp.generate_key("a", key, alg="ecdsa-p256")
    with pytest.raises(ValueError, match="unknown protection"):
        hampp.sign("x", key, protection="strong")
    with pytest.raises(ValueError, match="unknown protection"):
        hampp.verify(hampp.sign("x", key), pub, min_protection="strong")
    # not a point on the curve (x = 1), a second spelling of a point (SEC1 tag 05), a wrong length
    for bad in ["02" + "00" * 31 + "01", "05" + pub[2:], pub + "00"]:
        with pytest.raises(ValueError, match="public key"):
            hampp.verify("x", bad)


def test_tpm_key_file_gets_a_clear_message(tmp_path):
    # TPM keys are valid, but only the command line tool (built with the `tpm` feature) can use them
    key = tmp_path / "t.json"
    key.write_text(
        '{"alg":"ecdsa-p256-tpm","agent_id":"t","instance_id":"00","public":"00",'
        '"tpm_public":"","tpm_private":""}'
    )
    key.chmod(0o600)
    for call in (lambda: hampp.sign("x", str(key)), lambda: hampp.public_key(str(key))):
        with pytest.raises(ValueError, match="TPM key.*command line tool") as e:
            call()
        assert "invalid key file" not in str(e.value)
