"""HAMPP: signed agent messages in an invisible zero-width envelope."""
import json as _json

from ._native import annotate, generate_key, public_key, sign, strip
from ._native import verify_json as _verify_json

__all__ = ["generate_key", "public_key", "sign", "verify", "annotate", "strip"]


def verify(text: str, public_key_hex: str) -> dict:
    """Return the verdict as a dict; `code` is e.g. 'authenticated:signed-by-agent'."""
    return _json.loads(_verify_json(text, public_key_hex))
