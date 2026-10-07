#!/usr/bin/env python3
"""Independent HAMPP/1 verifier for spec/vectors/*.json (spec-only implementation)."""
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SYMS = ["​", "‌", "‍", "⁠"]
START, END = "⁤", "⁣"


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def extract(text: str):
    s = text.rfind(START)
    if s < 0:
        return text, "missing", None
    e = text.find(END, s + 1)
    if e < 0:
        return text[:s], "corrupt", None
    visible = text[:s] + text[e + 1:]
    body = text[s + 1:e]
    if any(c not in SYMS for c in body) or len(body) % 4:
        return visible, "corrupt", None
    idx = [SYMS.index(c) for c in body]
    data = bytes((idx[i] << 6) | (idx[i + 1] << 4) | (idx[i + 2] << 2) | idx[i + 3] for i in range(0, len(idx), 4))
    if len(data) < 4 or int.from_bytes(data[:2], "big") != len(data) - 4:
        return visible, "corrupt", None
    if crc16(data[:-2]) != int.from_bytes(data[-2:], "big"):
        return visible, "corrupt", None
    return visible, "ok", data[2:-2]


def extract_visible(text: str):
    t = text.rstrip(WHITE_SPACE)
    i = t.rfind("\n[hampp1:")
    if not t.endswith("]") or i < 0:
        return text, "missing", None
    try:
        data = bytes.fromhex(t[i + 9:-1])
    except ValueError:
        return t[:i], "corrupt", None
    if len(data) < 2 or crc16(data[:-2]) != int.from_bytes(data[-2:], "big"):
        return t[:i], "corrupt", None
    return t[:i], "ok", data[:-2]


def varint(buf, i):
    r, shift = 0, 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << shift
        if not b & 0x80:
            return r, i
        shift += 7


def parse_header(payload: bytes):
    flags, suite = payload[3], payload[4]
    key_id, session_id = payload[5:13], payload[13:21]
    seq, i = varint(payload, 21)
    ts, i = varint(payload, i)
    prev, sig = payload[i:i + 16], payload[i + 16:i + 80]
    return flags, suite, key_id, session_id, seq, ts, prev, sig


WHITE_SPACE = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680" + "".join(chr(c) for c in range(0x2000, 0x200B)) + "\u2028\u2029\u202f\u205f\u3000"


def payload_hash(visible: str) -> bytes:
    return hashlib.sha256(visible.replace("\r\n", "\n").rstrip(WHITE_SPACE).encode()).digest()


def signing_input(flags, suite, key_id, session_id, seq, ts, ph, prev) -> bytes:
    return (b"HAMPP/1 msg" + bytes([1, flags, suite]) + key_id + session_id
            + seq.to_bytes(8, "big") + ts.to_bytes(8, "big") + ph + prev)


def verify(text: str, pubkey: bytes) -> str:
    visible, st, payload = extract(text)
    if st == "missing":
        visible, st, payload = extract_visible(text)
    if st == "missing":
        return "unverified:envelope-missing"
    if st == "corrupt":
        return "unverified:envelope-corrupt"
    if payload[:2] != b"HP" or payload[2] != 1:
        return "invalid:unsupported-version"
    flags, suite, key_id, session_id, seq, ts, prev, sig = parse_header(payload)
    if suite != 1:
        return "invalid:unsupported-suite"
    if hashlib.sha256(pubkey).digest()[:8] != key_id:
        return "unverified:unknown-key"
    inp = signing_input(flags, suite, key_id, session_id, seq, ts, payload_hash(visible), prev)
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, inp)
    except InvalidSignature:
        return "invalid:signature-invalid"
    return "authenticated:signed-by-agent"


P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
PROTECTION = ["software", "bound", "attested"]


def verify_p256(pubkey: bytes, sig: bytes, msg: bytes) -> bool:
    """ECDSA P-256 / SHA-256, raw r||s, high s rejected (spec/PROTOCOL.md section 2)."""
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if s > P256_N // 2:
        return False
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
        key.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_protection(text: str, pubkey: bytes, registry=None, minimum=None):
    """Sections 2, 4 and 8 of spec/PROTOCOL.md. Returns (code, protection or None, notes)."""
    visible, st, payload = extract(text)
    if st == "missing":
        visible, st, payload = extract_visible(text)
    if st == "missing":
        return "unverified:envelope-missing", None, []
    if st == "corrupt":
        return "unverified:envelope-corrupt", None, []
    if payload[:2] != b"HP" or payload[2] != 1:
        return "invalid:unsupported-version", None, []
    flags, suite, key_id, session_id, seq, ts, prev, sig = parse_header(payload)
    if flags & ~0b111 or (flags >> 1) & 3 == 3:
        return "unverified:envelope-corrupt", None, []
    if suite not in (1, 2):
        return "invalid:unsupported-suite", None, []
    if hashlib.sha256(pubkey).digest()[:8] != key_id:
        return "unverified:unknown-key", None, []
    inp = signing_input(flags, suite, key_id, session_id, seq, ts, payload_hash(visible), prev)
    if (1 if len(pubkey) == 32 else 2) != suite:
        return "invalid:signature-invalid", None, []
    if suite == 1:
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, inp)
        except InvalidSignature:
            return "invalid:signature-invalid", None, []
    elif not verify_p256(pubkey, sig, inp):
        return "invalid:signature-invalid", None, []
    # Section 8: attested counts as bound (no evidence format); the registry caps the claim.
    header = (flags >> 1) & 3
    notes = []
    if header == 2:
        notes.append("attestation-not-verified")
    header = min(header, 1)
    if registry is None:
        level = header
    else:
        known = PROTOCOL_INDEX[registry]
        level = min(header, min(known, 1))
        if header > known:
            notes.append("protection-capped")
    if minimum is not None and level < PROTOCOL_INDEX[minimum]:
        return "unverified:protection-too-low", PROTECTION[level], notes
    return "authenticated:signed-by-agent", PROTECTION[level], notes


PROTOCOL_INDEX = {name: i for i, name in enumerate(PROTECTION)}


def check_protection(path: str) -> int:
    failures = 0
    for v in json.load(open(path, encoding="utf-8")):
        text = bytes.fromhex(v["signed_text_hex"]).decode("utf-8")
        got = verify_protection(text, bytes.fromhex(v["public_key_hex"]),
                                v.get("registry_protection"), v.get("min_protection"))
        want = (v["expected"], v["expected_protection"], v["expected_notes"])
        ok = got == want
        failures += not ok
        print(("ok   " if ok else "FAIL ") + v["name"] + ("" if ok else f" got={got} expected={want}"))
    return 1 if failures else 0


def p256_pub_of(scalar_hex: str) -> bytes:
    key = ec.derive_private_key(int(scalar_hex, 16), ec.SECP256R1())
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def check_handshake_p256(path: str) -> int:
    """Handshake and session with suite 2 (spec/PROTOCOL.md sections 5, 6 and 8)."""
    v = json.load(open(path, encoding="utf-8"))
    alice_pk, bob_pk = p256_pub_of(v["alice_scalar_hex"]), p256_pub_of(v["bob_scalar_hex"])
    na, nb = bytes.fromhex(v["nonce_a_hex"]), bytes.fromhex(v["nonce_b_hex"])
    # fixed parameters of the vector: versions [1], suites [2], no capabilities, agent ids alice/bob
    t = hashlib.sha256(
        b"HAMPP/1 transcript"
        + put(bytes([1])) + put(bytes([2])) + put_caps([])
        + put(b"alice") + put(bytes([1]) * 16) + put(alice_pk) + put(na)
        + put(bytes([1, 2])) + put_caps([])
        + put(b"bob") + put(bytes([2]) * 16) + put(bob_pk) + put(nb)
    ).digest()
    failures = 0

    def report(name, ok):
        nonlocal failures
        failures += not ok
        print(("ok   " if ok else "FAIL ") + name)

    report("transcript", t.hex() == v["transcript_hex"])
    report("sig_b", verify_p256(bob_pk, bytes.fromhex(v["sig_b_hex"]), b"HAMPP/1 hs B" + t))
    report("sig_a", verify_p256(alice_pk, bytes.fromhex(v["sig_a_hex"]), b"HAMPP/1 hs A" + t))
    sid = hashlib.sha256(b"HAMPP/1 session" + alice_pk + bob_pk + na + nb + bytes([1, 2])).digest()[:8]
    report("session_id", sid.hex() == v["session_id_hex"])
    prev = bytes(16)
    for m in v["messages"]:
        text = bytes.fromhex(m["signed_text_hex"]).decode("utf-8")
        visible, st, payload = extract(text)
        ok = st == "ok"
        if ok:
            flags, suite, key_id, session_id, seq, ts, hprev, sig = parse_header(payload)
            ph = payload_hash(visible)
            inp = signing_input(flags, suite, key_id, session_id, seq, ts, ph, hprev)
            ok = (verify_p256(alice_pk, sig, inp) and suite == 2 and flags & 1 == 1
                  and PROTECTION[(flags >> 1) & 3] == m["protection"] and key_id == hashlib.sha256(alice_pk).digest()[:8]
                  and session_id == sid and seq == m["seq"] and ts == m["timestamp"] and hprev == prev
                  and visible == m["text"])
            prev = hashlib.sha256(ph + sig).digest()[:16]
        report(f"message {m['seq']}", ok)
    return 1 if failures else 0


def pub_of(seed_hex: str) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def check_lite(path: str) -> int:
    failures = 0
    for v in json.load(open(path, encoding="utf-8")):
        got = verify(bytes.fromhex(v["signed_text_hex"]).decode("utf-8"), pub_of(v["seed_hex"]))
        ok = got == v["expected"]
        failures += not ok
        print(("ok   " if ok else "FAIL ") + v["name"] + ("" if ok else f" got={got} expected={v['expected']}"))
    return 1 if failures else 0


def put(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def put_caps(caps) -> bytes:
    out = put(len(caps).to_bytes(4, "big"))
    for tag, critical, value in caps:
        out += put(bytes([tag, 1 if critical else 0])) + put(value)
    return out


def check_handshake(path: str) -> int:
    v = json.load(open(path, encoding="utf-8"))
    alice_pk, bob_pk = pub_of(v["alice_seed_hex"]), pub_of(v["bob_seed_hex"])
    na, nb = bytes.fromhex(v["nonce_a_hex"]), bytes.fromhex(v["nonce_b_hex"])
    # fixed parameters of the vector: versions [1], suites [1], no capabilities, agent ids alice/bob
    t = hashlib.sha256(
        b"HAMPP/1 transcript"
        + put(bytes([1])) + put(bytes([1])) + put_caps([])
        + put(b"alice") + put(bytes([1]) * 16) + put(alice_pk) + put(na)
        + put(bytes([1, 1])) + put_caps([])
        + put(b"bob") + put(bytes([2]) * 16) + put(bob_pk) + put(nb)
    ).digest()
    failures = 0

    def report(name, ok):
        nonlocal failures
        failures += not ok
        print(("ok   " if ok else "FAIL ") + name)

    report("transcript", t.hex() == v["transcript_hex"])
    for label, key, field in ((b"HAMPP/1 hs B", bob_pk, "sig_b_hex"), (b"HAMPP/1 hs A", alice_pk, "sig_a_hex")):
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(v[field]), label + t)
            report(field.replace("_hex", ""), True)
        except InvalidSignature:
            report(field.replace("_hex", ""), False)
    sid = hashlib.sha256(b"HAMPP/1 session" + alice_pk + bob_pk + na + nb + bytes([1, 1])).digest()[:8]
    report("session_id", sid.hex() == v["session_id_hex"])
    prev = bytes(16)
    for m in v["messages"]:
        text = bytes.fromhex(m["signed_text_hex"]).decode("utf-8")
        visible, st, payload = extract(text)
        ok = st == "ok"
        if ok:
            flags, suite, key_id, session_id, seq, ts, hprev, sig = parse_header(payload)
            ph = payload_hash(visible)
            inp = signing_input(flags, suite, key_id, session_id, seq, ts, ph, hprev)
            try:
                Ed25519PublicKey.from_public_bytes(alice_pk).verify(sig, inp)
            except InvalidSignature:
                ok = False
            ok = ok and session_id == sid and seq == m["seq"] and ts == m["timestamp"] and hprev == prev
            prev = hashlib.sha256(ph + sig).digest()[:16]
        report(f"message {m['seq']}", ok)
    return 1 if failures else 0


def main(argv) -> int:
    if len(argv) >= 2 and argv[0] == "--handshake":
        return check_handshake(argv[1])
    if len(argv) >= 2 and argv[0] == "--handshake-p256":
        return check_handshake_p256(argv[1])
    if len(argv) >= 2 and argv[0] == "--protection":
        return check_protection(argv[1])
    return check_lite(argv[0] if argv else "spec/vectors/lite.json")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
