#!/usr/bin/env python3
"""Antigravity PreToolUse hook refusing forbidden multiplayer.tech secret material.

Zero external dependencies (Python 3 stdlib only). Reads Antigravity camelCase
protojson on stdin (`toolCall.name`, `toolCall.args`) and emits:
- `{"decision": "deny", "reason": "..."}` on detected secrets, malformed payloads,
  excessive nesting, or unexpected errors (fail closed), without echoing secrets.
- `{"decision": "ask"}` on clean payloads so normal host approval policy applies
  (never auto-approving write tools).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from typing import Any

RECOVERY_KEY_DOMAIN_SEP = b"mp-recovery-v1:"
MAX_RECOVERY_WINDOW_TOKENS = 16
MAX_RECOVERY_WINDOW_SPAN = 160
MAX_SCAN_DEPTH = 8
MAX_SAFE_INTEGER = 9007199254740991
RECOVERY_SEPS = frozenset("-_.,/:| \t\r\n\f\v")
DECIMAL_ID_RE = re.compile(r"^[0-9]{1,16}$")
SAFE_INT_SCALAR_KEYS = frozenset({"party_id", "cursor_epoch", "target_device_id", "after_seq"})
SAFE_INT_LIST_KEYS = frozenset({"drop_ids"})

CROCKFORD_MAP = {
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

CREDENTIAL_KEYS = frozenset(
    {"device_secret", "device_cwt", "root_key_hex", "root_secret", "private_key", "recovery_key"}
)

SECRET_PATTERNS = (
    ("invite_token", re.compile(r"(?:^|[^A-Za-z0-9])mpinv1_[A-Za-z0-9_-]{43,}", re.IGNORECASE)),
    ("party_invite", re.compile(r"(?:^|[^A-Za-z0-9])mppi1_[0-9]+_[A-Za-z0-9_-]{43,}", re.IGNORECASE)),
    ("invite_token", re.compile(r"(?:^|[^A-Za-z0-9])(?:mpcs1_|mpguest1_)[A-Za-z0-9_-]{16,}", re.IGNORECASE)),
    ("device_link_token", re.compile(r"(?:^|[^A-Za-z0-9])mpdl1_[A-Za-z0-9_-]{43,}", re.IGNORECASE)),
    ("private_key_pem", re.compile(r"-----(?:BEGIN|END) [A-Z0-9 -]{0,48}(?:PRIVATE|RECOVERY|SECRET) KEY-----", re.IGNORECASE)),
    ("recovery_file", re.compile(r'(?:"format"\s*:\s*"mpkey"|MPKEY1|TVBLRVkxAA|"kdf"\s*:\s*"argon2id"[\s\S]{0,256}"ciphertext")', re.IGNORECASE)),
    ("device_credential", re.compile(r'["\']?(?:device_secret|device_cwt|root_key_hex|root_secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]{16,}', re.IGNORECASE)),
)

INVITE_FRAGMENT_RE = re.compile(
    r"(?:https?://)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)/[^\s#]+|[^\s#]+/(?:p/)?i/[A-Za-z0-9_-]+)#[^\s]{8,}",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
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
    if len(syms) != 55 or (syms[-1] & 0x07) != 0 or len(set(syms)) <= 1:
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


def _contains_recovery_key(norm: str) -> bool:
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
        vals: list[int] = []
        for ch in window:
            val = CROCKFORD_MAP.get(ch)
            if val is not None:
                vals.append(val)
                if len(vals) >= 40 and len(set(vals[:40])) >= 2:
                    return True
                if len(vals) >= 55:
                    break
            elif ch in RECOVERY_SEPS:
                continue
            else:
                break

    n = len(norm)
    i = 0
    while i < n:
        if norm[i] not in CROCKFORD_MAP or (i > 0 and norm[i - 1] in CROCKFORD_MAP):
            i += 1
            continue
        syms: list[tuple[int, int, bool, bool]] = []
        j = i
        at_b = True
        while j < n:
            ch = norm[j]
            val = CROCKFORD_MAP.get(ch)
            if val is not None:
                syms.append((val, j, at_b, False))
                at_b = False
                j += 1
            elif ch in RECOVERY_SEPS:
                if syms:
                    v, p, sb, _ = syms[-1]
                    syms[-1] = (v, p, sb, True)
                at_b = True
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
                if sum(1 for item in syms[k : k + 55] if item[2]) > MAX_RECOVERY_WINDOW_TOKENS:
                    continue
                if _verify_unprefixed_recovery_window([item[0] for item in syms[k : k + 55]]):
                    return True
        i = j + 1
    return False


def detect_secret(text: str, *, allow_invite_fragment: bool = False) -> str | None:
    norm = _normalize(text)
    candidates = (text, norm) if norm != text else (text,)
    for cand in candidates:
        for kind, pattern in SECRET_PATTERNS:
            if pattern.search(cand):
                return kind
        if not allow_invite_fragment and INVITE_FRAGMENT_RE.search(cand):
            return "invite_url_fragment"
    if _contains_recovery_key(norm):
        return "recovery_key"
    return None


def _scan_b64_payload(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not compact:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True)
    except Exception:
        return None
    if decoded.startswith(b"MPKEY1\x00"):
        return "recovery_file"
    text = decoded.decode("utf-8", errors="ignore")
    return detect_secret(text, allow_invite_fragment=False)


def scan_value(
    value: Any,
    *,
    tool_name: str = "",
    key_name: str = "",
    depth: int = 0,
) -> str | None:
    if depth > MAX_SCAN_DEPTH:
        return "nesting_depth_exceeded"
    if value is None:
        return None
    allow_frag = tool_name.endswith("party_join") and key_name == "target"
    if isinstance(value, str):
        if key_name.lower() in CREDENTIAL_KEYS and len(value.strip()) >= 16:
            return "device_credential"
        hit = detect_secret(value, allow_invite_fragment=allow_frag)
        if hit is not None:
            return hit
        if key_name == "payload_b64":
            return _scan_b64_payload(value)
        return None
    if isinstance(value, list):
        for item in value:
            hit = scan_value(item, tool_name=tool_name, key_name=key_name, depth=depth + 1)
            if hit is not None:
                return hit
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            k_str = str(k)
            k_hit = detect_secret(k_str, allow_invite_fragment=False)
            if k_hit is not None:
                return k_hit
            v_hit = scan_value(v, tool_name=tool_name, key_name=k_str, depth=depth + 1)
            if v_hit is not None:
                return v_hit
    return None


def _parse_safe_int_str(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not DECIMAL_ID_RE.fullmatch(stripped):
        return None
    parsed = int(stripped)
    if 0 <= parsed <= MAX_SAFE_INTEGER:
        return parsed
    return None


def _coerce_safe_int_fields(args_obj: Any) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Coerce decimal-string 53-bit IDs to exact ints for mp-outpost MCP tools.

    Antigravity replays historical numeric tool arguments using 15-digit float
    formatting (`1.679...e+15`), which can drop the 16th digit of `party_id` or
    `cursor_epoch`. Allowing callers to pass exact decimal strings preserves all
    16 digits in conversation history while delivering exact JSON integers to
    `mp-outpost` via PreToolUse `overwrite`.

    Returns `(full_coerced_dict, changed_keys_dict)` if any field was coerced,
    otherwise `None`.
    """
    if not isinstance(args_obj, dict):
        return None
    changed: dict[str, Any] = {}
    for key, val in args_obj.items():
        if key in SAFE_INT_SCALAR_KEYS:
            parsed = _parse_safe_int_str(val)
            if parsed is not None:
                changed[key] = parsed
        elif key in SAFE_INT_LIST_KEYS and isinstance(val, list):
            new_list: list[Any] = []
            list_changed = False
            for item in val:
                parsed = _parse_safe_int_str(item)
                if parsed is not None:
                    new_list.append(parsed)
                    list_changed = True
                else:
                    new_list.append(item)
            if list_changed:
                changed[key] = new_list
    if not changed:
        return None
    full = dict(args_obj)
    full.update(changed)
    return full, changed


def _deny(reason: str) -> int:
    print(json.dumps({"decision": "deny", "reason": reason}))
    return 0


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return _deny("Refused outbound multiplayer tool call: empty hook payload (fail closed).")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return _deny("Refused outbound multiplayer tool call: malformed hook payload (fail closed).")
        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            return _deny("Refused outbound multiplayer tool call: missing toolCall object (fail closed).")
        tool_name = str(tool_call.get("name") or "")
        args = tool_call.get("args")
        effective_tool_name = tool_name
        scan_target: Any = args
        is_lazy_mcp = tool_name in ("call_mcp_tool", "mcp_tool")
        lazy_args_key: str | None = None
        # Antigravity loads plugin MCP tools lazily via `call_mcp_tool(ServerName, ToolName, Arguments)`.
        if is_lazy_mcp:
            if not isinstance(args, dict):
                return _deny("Refused MCP tool call: malformed call_mcp_tool args (fail closed).")
            server_name = str(args.get("ServerName") or args.get("serverName") or args.get("server_name") or "")
            if "multiplayer" not in server_name.lower():
                # Unrelated MCP server: defer to Antigravity's normal permission policy.
                print('{"decision": "ask"}')
                return 0
            effective_tool_name = str(args.get("ToolName") or args.get("toolName") or args.get("tool_name") or "")
            if "Arguments" in args:
                lazy_args_key = "Arguments"
                scan_target = args.get("Arguments")
            elif "arguments" in args:
                lazy_args_key = "arguments"
                scan_target = args.get("arguments")
            else:
                scan_target = args
        secret_kind = scan_value(scan_target, tool_name=effective_tool_name)
        if secret_kind is not None:
            return _deny(
                f"Refused outbound multiplayer tool call: detected forbidden secret material ({secret_kind})."
            )
        coerced = _coerce_safe_int_fields(scan_target)
        if coerced is not None:
            full_coerced, changed_only = coerced
            if is_lazy_mcp and lazy_args_key is not None:
                print(json.dumps({"decision": "ask", "overwrite": {lazy_args_key: full_coerced}}))
                return 0
            if not is_lazy_mcp:
                print(json.dumps({"decision": "ask", "overwrite": changed_only}))
                return 0
        # Defer to Antigravity's normal permission policy (respects Always Allow
        # cache without auto-approving write tools).
        print('{"decision": "ask"}')
        return 0
    except Exception:
        return _deny("Refused outbound multiplayer tool call: secret guard error (fail closed).")


if __name__ == "__main__":
    raise SystemExit(main())
