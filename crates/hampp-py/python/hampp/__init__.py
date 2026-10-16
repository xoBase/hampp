"""HAMPP: signed agent messages in an invisible zero-width envelope."""
import json as _json

from ._native import annotate, generate_key, public_key, sign, sign_detached, strip
from ._native import verify_detached_json as _verify_detached_json
from ._native import verify_json as _verify_json

__all__ = ["generate_key", "public_key", "sign", "sign_detached", "verify", "verify_detached", "annotate", "strip"]


def verify(text: str, public_key_hex: str, min_protection: str = None) -> dict:
    """Return the verdict as a dict; `code` is e.g. 'authenticated:signed-by-agent'.

    `public_key_hex` is an Ed25519 key (64 hex characters) or a P-256 key (66). With
    `min_protection` ('software', 'bound' or 'attested') weaker messages come back as
    'unverified:protection-too-low'.
    """
    return _json.loads(_verify_json(text, public_key_hex, min_protection))


def verify_detached(text: str, signature: str, public_key_hex: str, min_protection: str = None) -> dict:
    """Check a detached signature (see `sign_detached`) against `text`, which is taken literally.

    Same verdict dict as `verify`; `visible` is `text`. A missing or malformed `signature` gives
    'unverified:envelope-missing' or 'unverified:envelope-corrupt', never an exception.
    """
    return _json.loads(_verify_detached_json(text, signature, public_key_hex, min_protection))
