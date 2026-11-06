"""Verify OrsunPay webhook signatures before parsing the original body bytes."""

import hashlib
import hmac
import re
import time


_MAX_SAFE_INTEGER = 9007199254740991
_DEFAULT_NOW = object()
# String.trim() whitespace from the published Node.js example. Python's default
# str.strip() also accepts some control characters that JavaScript does not.
_HEADER_WHITESPACE = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def _utf8_key(secret):
    # Match Node's UTF-8 encoding even for JSON strings containing isolated
    # UTF-16 surrogates: replace invalid sequences with U+FFFD, not question marks.
    return (
        secret.encode("utf-16-le", errors="surrogatepass")
        .decode("utf-16-le", errors="replace")
        .encode("utf-8")
    )


def verify_webhook(raw_body, header, secrets, now=_DEFAULT_NOW):
    """Return whether any supplied signing secret authenticates raw_body.

    raw_body must be bytes, never decoded text or a parsed JSON value. Pass the
    complete issued secret string in a nonempty list; do not decode its suffix.
    now is an optional integer Unix timestamp in seconds, for deterministic use.
    Only omission uses the current clock; an explicit None is invalid.
    At the HTTP boundary also limit body size and reject duplicate header lines.
    """
    if not isinstance(raw_body, bytes) or not isinstance(header, str):
        return False
    # JavaScript counts UTF-16 code units, including for non-BMP characters.
    if len(header) > 4096:
        return False
    if len(header.encode("utf-16-le", errors="surrogatepass")) > 8192:
        return False
    if not isinstance(secrets, list) or not secrets:
        return False
    if now is _DEFAULT_NOW:
        now = int(time.time())
    if (
        not isinstance(now, int)
        or isinstance(now, bool)
        or abs(now) > _MAX_SAFE_INTEGER
    ):
        return False

    parts = [part.strip(_HEADER_WHITESPACE) for part in header.split(",")]
    timestamps = [part for part in parts if part.startswith("t=")]
    if len(timestamps) != 1 or not re.fullmatch(r"t=[0-9]+", timestamps[0]):
        return False
    timestamp_text = timestamps[0][2:]
    # Bound before integer conversion without discarding the signed text.
    significant = timestamp_text.lstrip("0") or "0"
    if len(significant) > 16:
        return False
    timestamp = int(significant)
    if timestamp > _MAX_SAFE_INTEGER or abs(now - timestamp) > 300:
        return False

    signatures = [
        bytes.fromhex(part[3:])
        for part in parts
        if re.fullmatch(r"v1=[0-9a-f]{64}", part, flags=re.IGNORECASE)
    ]
    if not signatures:
        return False
    for secret in secrets:
        if not isinstance(secret, str) or not secret:
            continue
        expected = hmac.new(_utf8_key(secret), digestmod=hashlib.sha256)
        expected.update(timestamp_text.encode("ascii") + b".")
        expected.update(raw_body)
        digest = expected.digest()
        if any(hmac.compare_digest(digest, signature) for signature in signatures):
            return True
    return False
