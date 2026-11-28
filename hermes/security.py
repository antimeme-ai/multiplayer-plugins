"""Provenance fencing, URL fragment redaction, and outbound secret refusal matching mp-outpost v0.7.0."""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Final

RECOVERY_KEY_DOMAIN_SEP: Final[bytes] = b"mp-recovery-v1:"
MAX_RECOVERY_WINDOW_TOKENS: Final[int] = 16
MAX_RECOVERY_WINDOW_SPAN: Final[int] = 160

_INVITE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[^A-Za-z0-9])mpinv1_[A-Za-z0-9_-]{43,}",
    re.IGNORECASE,
)
_PARTY_INVITE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[^A-Za-z0-9])mppi1_[0-9]+_[A-Za-z0-9_-]{43,}",
    re.IGNORECASE,
)
_SESSION_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:mpcs1_|mpguest1_)[A-Za-z0-9_-]{16,}",
    re.IGNORECASE,
)
_DEVICE_LINK_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[^A-Za-z0-9])mpdl1_[A-Za-z0-9_-]{43,}",
    re.IGNORECASE,
)
_PEM_PRIVATE_RE: Final[re.Pattern[str]] = re.compile(
    r"-----(?:BEGIN|END) [A-Z0-9 -]{0,48}(?:PRIVATE|RECOVERY|SECRET) KEY-----",
    re.IGNORECASE,
)
_MPKEY_RE: Final[re.Pattern[str]] = re.compile(
    r'(?:"format"\s*:\s*"mpkey"|MPKEY1|TVBLRVkxAA|"kdf"\s*:\s*"argon2id"[\s\S]{0,256}"ciphertext")',
    re.IGNORECASE,
)
_DEVICE_CRED_RE: Final[re.Pattern[str]] = re.compile(
    r'(?:["\']?(?:device_secret|device_cwt|root_key_hex|root_secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]{16,})',
    re.IGNORECASE,
)
_ANGLE_RUN_RE: Final[re.Pattern[str]] = re.compile(r"<{3,}|>{3,}")
_URL_FRAGMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"((?:https?://)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)/[^\s#\"']+?|[^\s#\"']+?/(?:p/)?i/[A-Za-z0-9_-]+))#[A-Za-z0-9_-]+",
    re.IGNORECASE,
)
_INVITE_FRAGMENT_TEST_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:https?://)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)/[^\s#\"']+|[^\s#\"']+/(?:p/)?i/[A-Za-z0-9_-]+)#[^\s]{8,}",
    re.IGNORECASE,
)

# Secret regexes for Hermes `ctx.register_redaction_patterns(...)` (each starts with >=2 literal chars).
REDACTION_PATTERNS: Final[tuple[str, ...]] = (
    r"mpinv1_[A-Za-z0-9_-]{20,}",
    r"mppi1_[0-9]+_[A-Za-z0-9_-]{20,}",
    r"mpdl1_[A-Za-z0-9_-]{20,}",
    r"mprk1_[A-Za-z0-9_-]{20,}",
    r"mpcs1_[A-Za-z0-9_-]{16,}",
    r"mpguest1_[A-Za-z0-9_-]{16,}",
)

_CROCKFORD_MAP: Final[dict[str, int]] = {
    "0": 0, "O": 0, "o": 0,
    "1": 1, "I": 1, "i": 1, "L": 1, "l": 1,
    "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
    "A": 10, "a": 10, "B": 11, "b": 11, "C": 12, "c": 12, "D": 13, "d": 13,
    "E": 14, "e": 14, "F": 15, "f": 15, "G": 16, "g": 16, "H": 17, "h": 17,
    "J": 18, "j": 18, "K": 19, "k": 19, "M": 20, "m": 20, "N": 21, "n": 21,
    "P": 22, "p": 22, "Q": 23, "q": 23, "R": 24, "r": 24, "S": 25, "s": 25,
    "T": 26, "t": 26, "V": 27, "v": 27, "W": 28, "w": 28, "X": 29, "x": 29,
    "Y": 30, "y": 30, "Z": 31, "z": 31,
}

_RECOVERY_SEPS: Final[frozenset[str]] = frozenset("-_.,/:| \t\r\n\f\v")


class SecretRefusalError(ValueError):
    """Raised when outbound payload contains forbidden secret material.

    Security invariant: error messages NEVER echo or include the matched secret.
    """

    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(f"outbound payload refused: detected forbidden secret material ({kind})")


def redact_url_fragments(text: str) -> str:
    """Redact `#fragment` invite secrets on multiplayer.tech / clank.party / mp.gg and /i/ URLs."""
    return _URL_FRAGMENT_RE.sub(r"\1#[REDACTED]", text)


def redact_payload(value: object) -> object:
    """Recursively redact `#fragment` invite secrets from JSON-like return payloads."""
    if isinstance(value, str):
        return redact_url_fragments(value)
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, dict):
        return {k: redact_payload(v) for k, v in value.items()}
    return value


def sanitize_peer_text(raw: str) -> str:
    """Strip C0 (except \\n and \\t), DEL, C1, Unicode separators, BiDi, zero-width, and Tag chars."""
    out: list[str] = []
    for ch in raw:
        if ch in ("\n", "\t"):
            out.append(ch)
            continue
        cp = ord(ch)
        if (
            cp <= 0x1F
            or cp == 0x7F
            or 0x80 <= cp <= 0x9F
            or cp in (0x2028, 0x2029, 0x061C, 0x200E, 0x200F, 0xFEFF)
            or 0x202A <= cp <= 0x202E
            or 0x2066 <= cp <= 0x2069
            or 0x200B <= cp <= 0x200D
            or 0xE0000 <= cp <= 0xE007F
        ):
            continue
        out.append(ch)
    return "".join(out)


def sanitize_single_line(raw: str) -> str:
    """Sanitize metadata values (handles, scopes) to a single line with no CR/LF/tabs."""
    return " ".join(sanitize_peer_text(raw).replace("\n", " ").replace("\t", " ").split())


def break_angle_runs(text: str) -> str:
    """Break any contiguous run of >= 3 '<' or '>' into space-separated characters."""
    return _ANGLE_RUN_RE.sub(lambda m: " ".join(m.group(0)), text)


def fence_peer_text(raw: str, nonce: int | None = None) -> tuple[str, str]:
    """Wrap untrusted remote peer text in a per-response CSPRNG nonce fence.

    Returns ``(fenced_text, nonce_hex)``. Neutralizes any case-insensitive occurrence
    of the nonce and any run of >= 3 angle brackets inside the payload.
    """
    if nonce is None:
        nonce = secrets.randbits(64)
    nonce_hex = f"{nonce & 0xFFFFFFFFFFFFFFFF:016x}"
    clean = sanitize_peer_text(raw)
    neutralized = re.sub(re.escape(nonce_hex), "[redacted-nonce]", clean, flags=re.IGNORECASE)
    neutralized = break_angle_runs(neutralized)
    fenced = (
        f"<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_{nonce_hex}>>>\n"
        f"{neutralized}\n"
        f"<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END_{nonce_hex}>>>"
    )
    return fenced, nonce_hex


def _normalize_recovery_chars(text: str) -> str:
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp == 0x00AD or 0x200B <= cp <= 0x200F or cp in (0x2060, 0xFEFF):
            continue
        if 0xFF01 <= cp <= 0xFF5E:
            out.append(chr(cp - 0xFF01 + 0x21))
        elif 0x2010 <= cp <= 0x2015 or cp == 0x2212:
            out.append("-")
        elif cp == 0x3000 or (not ch.isascii() and ch.isspace()):
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _verify_unprefixed_recovery_window(syms: list[int]) -> bool:
    if len(syms) != 55:
        return False
    if (syms[-1] & 0x07) != 0:
        return False
    if len(set(syms)) <= 1:
        return False

    payload = bytearray()
    bit_buf = 0
    bit_len = 0
    for val in syms:
        bit_buf = (bit_buf << 5) | val
        bit_len += 5
        while bit_len >= 8:
            bit_len -= 8
            payload.append((bit_buf >> bit_len) & 0xFF)
    if len(payload) != 34 or bit_len != 3 or (bit_buf & 0x07) != 0:
        return False

    digest = hashlib.sha256(RECOVERY_KEY_DOMAIN_SEP + bytes(payload[:32])).digest()
    return payload[32] == digest[0] and payload[33] == digest[1]


def _contains_recovery_key(text: str) -> bool:
    norm = _normalize_recovery_chars(text)
    lower = norm.lower()

    start = 0
    while True:
        idx = lower.find("mprk1_", start)
        if idx < 0:
            break
        start = idx + 6
        window = norm[start : start + 256]
        if not window or window[0] in (" ", "\t"):
            continue
        crockford_vals: list[int] = []
        for ch in window:
            val = _CROCKFORD_MAP.get(ch)
            if val is not None:
                crockford_vals.append(val)
                if len(crockford_vals) >= 40 and len(set(crockford_vals[:40])) >= 2:
                    return True
                if len(crockford_vals) >= 55:
                    break
            elif ch in _RECOVERY_SEPS:
                continue
            else:
                break

    n = len(norm)
    i = 0
    while i < n:
        if norm[i] not in _CROCKFORD_MAP:
            i += 1
            continue
        if i > 0 and norm[i - 1] in _CROCKFORD_MAP:
            i += 1
            continue
        syms: list[tuple[int, int, bool, bool]] = []
        j = i
        at_boundary = True
        while j < n:
            ch = norm[j]
            val = _CROCKFORD_MAP.get(ch)
            if val is not None:
                syms.append((val, j, at_boundary, False))
                at_boundary = False
                j += 1
            elif ch in _RECOVERY_SEPS:
                if syms:
                    v, p, sb, _ = syms[-1]
                    syms[-1] = (v, p, sb, True)
                at_boundary = True
                j += 1
            else:
                break
        if syms:
            v, p, sb, _ = syms[-1]
            syms[-1] = (v, p, sb, True)
        if len(syms) >= 55:
            for k in range(0, len(syms) - 54):
                first = syms[k]
                last = syms[k + 54]
                if not first[2] or not last[3]:
                    continue
                if last[1] - first[1] > MAX_RECOVERY_WINDOW_SPAN:
                    continue
                token_starts = sum(1 for item in syms[k : k + 55] if item[2])
                if token_starts > MAX_RECOVERY_WINDOW_TOKENS:
                    continue
                if _verify_unprefixed_recovery_window([item[0] for item in syms[k : k + 55]]):
                    return True
        i = j + 1

    return False


def detect_secret_kind(payload: str | bytes) -> str | None:
    """Return the matched secret kind if payload contains forbidden secret material.

    Checks both raw text and zero-width/fullwidth/dash-normalized text so obfuscated
    tokens (e.g., ``mpinv1_\\u200b...``, ``mpcs1_...``, ``mpguest1_...``, or fullwidth PEM
    headers) cannot bypass refusal.
    """
    text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
    norm = _normalize_recovery_chars(text)
    candidates = (text, norm) if norm != text else (text,)

    for candidate in candidates:
        if _INVITE_RE.search(candidate) or _PARTY_INVITE_RE.search(candidate) or _SESSION_TOKEN_RE.search(candidate):
            return "invite_token"
        if _DEVICE_LINK_RE.search(candidate):
            return "device_link_token"
        if _PEM_PRIVATE_RE.search(candidate):
            return "private_key_pem"
        if _MPKEY_RE.search(candidate):
            return "recovery_file"
        if _DEVICE_CRED_RE.search(candidate):
            return "device_credential"
        if _INVITE_FRAGMENT_TEST_RE.search(candidate):
            return "invite_url_fragment"
    if _contains_recovery_key(norm):
        return "recovery_key"
    return None


def refuse_secrets(payload: str | bytes) -> None:
    """Raise ``SecretRefusalError`` if ``payload`` contains forbidden secret material."""
    kind = detect_secret_kind(payload)
    if kind is not None:
        raise SecretRefusalError(kind)
