"""Tier 3 Hermes Gateway Platform Adapter wrapping mp-outpost CLI/daemon IPC."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Final

from .security import (
    SecretRefusalError,
    fence_peer_text,
    redact_url_fragments,
    refuse_secrets,
    sanitize_peer_text,
    sanitize_single_line,
)

LOGGER = logging.getLogger(__name__)

MAX_PARTY_WAIT_MS: Final[int] = 45_000
DEFAULT_PARTY_WAIT_MS: Final[int] = 25_000
DEFAULT_SUBPROCESS_GRACE_S: Final[float] = 15.0
MAX_SAFE_ID: Final[int] = (1 << 53) - 1
_AMBIGUOUS_SAY_FLAGS: Final[frozenset[str]] = frozenset({"--scope", "--to-device"})


class _StandaloneBasePlatformAdapter:
    """Fallback base class when running outside a Hermes Agent runtime.

    Inside Hermes Agent, ``BasePlatformAdapter`` is imported from Hermes's
    gateway package so ``MultiplayerPlatformAdapter`` subclasses it directly.
    """

    platform_name: str = "multiplayer"

    def __init__(self, config: Any = None, platform: Any = None) -> None:
        self.config: Any = dict(config) if isinstance(config, dict) else (config or {})
        self.platform: Any = platform or "multiplayer"

    async def connect(self, *, is_reconnect: bool = False) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    async def disconnect(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    async def start(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    async def stop(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: str | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError


def _resolve_hermes_gateway_types() -> tuple[type, Any, Any, Any, Any, bool]:
    for prefix in ("hermes_agent.gateway", "gateway", "hermes.gateway"):
        try:
            base_mod = __import__(f"{prefix}.platforms.base", fromlist=["BasePlatformAdapter", "SendResult"])
            base = getattr(base_mod, "BasePlatformAdapter", None)
            send_result = getattr(base_mod, "SendResult", None)
            if not isinstance(base, type):
                continue
            platform_enum = None
            msg_event = None
            msg_type = None
            with contextlib.suppress(ImportError):
                cfg_mod = __import__(f"{prefix}.config", fromlist=["Platform"])
                platform_enum = getattr(cfg_mod, "Platform", None)
            with contextlib.suppress(ImportError):
                ev_mod = __import__(f"{prefix}.platforms.event", fromlist=["MessageEvent", "MessageType"])
                msg_event = getattr(ev_mod, "MessageEvent", None)
                msg_type = getattr(ev_mod, "MessageType", None)
            return base, send_result, platform_enum, msg_event, msg_type, True
        except ImportError:
            continue
    return _StandaloneBasePlatformAdapter, None, None, None, None, False


(
    BasePlatformAdapter,
    _HermesSendResult,
    _HermesPlatform,
    _HermesMessageEvent,
    _HermesMessageType,
    _HAS_HERMES_BASE,
) = _resolve_hermes_gateway_types()


def _coerce_hermes_platform(platform: Any) -> Any:
    if platform is None:
        platform = "multiplayer"
    if _HermesPlatform is not None and isinstance(platform, str):
        try:
            return _HermesPlatform(platform)
        except (ValueError, TypeError):
            # Platform may not be registered yet during isolated standalone tests.
            return platform
    return platform


class OutpostError(RuntimeError):
    """Base error raised by mp-outpost CLI invocations."""


class OutpostTimeoutError(OutpostError):
    """Raised when an mp-outpost subprocess exceeds its bounded wall-clock budget."""


class OutpostEofError(OutpostError):
    """Raised when mp-outpost terminates abruptly with EOF / empty output."""


@dataclass(frozen=True)
class PeerProvenance:
    """Verified sender metadata resolved by the mp-outpost daemon."""

    party_id: int
    event_seq: int
    kind: str
    sender_account_id: int = 0
    sender_device_id: int = 0
    sender_handle: str = ""
    safety_number: str = ""
    room_scope: str = ""
    party_epoch: int = 0
    untrusted_remote: bool = True
    is_browser: bool = False
    sender_client: str = ""
    is_historical_catchup: bool = False


@dataclass(frozen=True)
class FencedPeerMessage:
    """Inbound party event with verified provenance separated from nonce-fenced peer data."""

    provenance: PeerProvenance
    fenced_body: str
    nonce: str
    raw_kind: str


@dataclass
class PartyCursor:
    """Tracks cursor position and daemon epoch across party_poll / party_wait calls."""

    party_id: int
    after_seq: int = 0
    daemon_epoch: int = 0
    cursor_reset_count: int = 0
    gap_possible_count: int = 0


MessageCallback = Callable[[FencedPeerMessage], Awaitable[None] | None]


def clamp_wait_timeout_ms(timeout_ms: int) -> int:
    """Clamp party_wait timeout_ms to mp-outpost's [0, 45000] ms contract."""
    if timeout_ms < 0:
        return 0
    if timeout_ms > MAX_PARTY_WAIT_MS:
        return MAX_PARTY_WAIT_MS
    return int(timeout_ms)


def _validate_safe_id(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > MAX_SAFE_ID:
        raise ValueError(f"{field_name} must be an integer in 1..={MAX_SAFE_ID}")
    return value


def _validate_safe_cli_token(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    cleaned = value.strip()
    if cleaned.startswith("-"):
        raise ValueError(f"{field_name} cannot start with '-'")
    refuse_secrets(cleaned)
    return cleaned


def _extract_cfg_dict(config: Any) -> dict[str, Any]:
    if isinstance(config, dict):
        return dict(config)
    extra = getattr(config, "extra", None)
    if isinstance(extra, dict):
        return dict(extra)
    return {}


class MultiplayerPlatformAdapter(BasePlatformAdapter):  # type: ignore[misc]
    """Hermes Gateway platform adapter for multiplayer.tech via ``mp-outpost``.

    Implements both Hermes ``BasePlatformAdapter`` lifecycle methods
    (``connect`` / ``disconnect`` / ``send``) and standalone helpers
    (``start`` / ``stop`` / ``send_message``).

    Security invariants:
    - Never reads ``root.key``, ``.mpkey``, ``device_secret``, or Hermes secret stores.
    - Refuses outbound secrets BEFORE spawning ``mp-outpost`` (secrets never enter argv).
    - Redacts ``#fragment`` invite secrets in error messages and logs.
    - Marks ``is_browser=True`` / ``sender_client in ("web", "browser")`` events as
      always untrusted remote input even under the local operator's own handle.
    - Wraps every inbound remote peer payload in a fresh per-message CSPRNG nonce fence.
    - Enforces bounded timeouts and clean ``SIGTERM``/``SIGKILL`` child shutdown.
    """

    platform_name: str = "multiplayer"
    name: str = "multiplayer"
    MAX_MESSAGE_LENGTH: int = 8192

    def __init__(
        self,
        config: Any = None,
        platform: Any = None,
        *,
        binary: str | None = None,
        party_id: int | None = None,
        state_dir: str | None = None,
        wait_timeout_ms: int = DEFAULT_PARTY_WAIT_MS,
        subprocess_grace_s: float = DEFAULT_SUBPROCESS_GRACE_S,
        on_message: MessageCallback | None = None,
        stop_on_eof: bool = False,
        max_consecutive_errors: int = 5,
        backoff_s: float = 0.25,
    ) -> None:
        cfg = _extract_cfg_dict(config)
        self._hermes_native_mode = _HAS_HERMES_BASE and platform is not None
        coerced_platform = _coerce_hermes_platform(platform)
        if _HAS_HERMES_BASE:
            super().__init__(config if config is not None else cfg, coerced_platform)
        else:
            super().__init__(cfg, coerced_platform)
        self._own_device_id: int = 0
        self.binary: str = binary or str(cfg.get("binary", "mp-outpost"))
        raw_party = party_id if party_id is not None else cfg.get("party_id")
        self.party_id: int | None = int(raw_party) if raw_party is not None else None
        self.state_dir: str | None = state_dir or cfg.get("state_dir")
        self.wait_timeout_ms: int = clamp_wait_timeout_ms(
            int(cfg.get("wait_timeout_ms", wait_timeout_ms))
        )
        self.subprocess_grace_s: float = max(
            0.1, float(cfg.get("subprocess_grace_s", subprocess_grace_s))
        )
        self.on_message: MessageCallback | None = on_message
        self.stop_on_eof: bool = bool(cfg.get("stop_on_eof", stop_on_eof))
        self.max_consecutive_errors: int = max(
            1, int(cfg.get("max_consecutive_errors", max_consecutive_errors))
        )
        self.backoff_s: float = max(0.0, float(cfg.get("backoff_s", backoff_s)))

        self.cursor: PartyCursor | None = (
            PartyCursor(party_id=_validate_safe_id(self.party_id, "party_id"))
            if self.party_id is not None
            else None
        )
        self._stop_event = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None
        self._active_procs: set[asyncio.subprocess.Process] = set()
        self.consecutive_errors: int = 0
        self.last_error: str | None = None

    def _base_argv(self) -> list[str]:
        argv = [self.binary]
        if self.state_dir:
            argv.extend(["--state-dir", self.state_dir])
        argv.append("--json")
        return argv

    async def _terminate_proc(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=2.0)

    async def _run_json(
        self,
        sub_args: list[str],
        *,
        timeout_s: float,
        stdin_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        argv = self._base_argv() + sub_args
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._active_procs.add(proc)
        try:
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes), timeout=timeout_s
                )
            except asyncio.TimeoutError as exc:
                await self._terminate_proc(proc)
                raise OutpostTimeoutError(
                    f"mp-outpost timed out after {timeout_s:.2f}s"
                ) from exc
            except asyncio.CancelledError:
                await self._terminate_proc(proc)
                raise
        finally:
            self._active_procs.discard(proc)

        stdout_text = stdout_b.decode("utf-8", errors="replace").strip()
        stderr_text = redact_url_fragments(stderr_b.decode("utf-8", errors="replace").strip())

        if not stdout_text:
            if proc.returncode in (0, None):
                raise OutpostEofError("mp-outpost closed stdout without a JSON response (EOF)")
            raise OutpostEofError(
                f"mp-outpost exited with code {proc.returncode} and empty stdout: {stderr_text[:200]}"
            )

        if proc.returncode != 0:
            safe_out = redact_url_fragments(stdout_text[:200])
            raise OutpostError(
                f"mp-outpost exited with code {proc.returncode}: {stderr_text[:200] or safe_out}"
            )

        try:
            parsed = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            raise OutpostError(f"invalid JSON from mp-outpost: {exc}") from exc

        if not isinstance(parsed, dict):
            raise OutpostError("expected JSON object from mp-outpost")
        return parsed

    async def status(self) -> dict[str, Any]:
        return await self._run_json(["party", "status"], timeout_s=self.subprocess_grace_s)

    async def list_parties(self) -> dict[str, Any]:
        return await self._run_json(["party", "list"], timeout_s=self.subprocess_grace_s)

    async def members(self, party_id: int) -> dict[str, Any]:
        pid = _validate_safe_id(party_id, "party_id")
        return await self._run_json(["party", "members", str(pid)], timeout_s=self.subprocess_grace_s)

    async def friends(self) -> dict[str, Any]:
        """List friends, live presence, and pending invites (falls back to `friend list` on older binaries)."""
        try:
            return await self._run_json(["friends"], timeout_s=self.subprocess_grace_s)
        except OutpostError as exc:
            if "unknown subcommand" in str(exc).lower():
                return await self._run_json(["friend", "list"], timeout_s=self.subprocess_grace_s)
            raise

    async def add_friend(self, handle: str) -> dict[str, Any]:
        """Send or accept a friend request by ``@handle`` after pre-exec secret refusal."""
        clean_handle = _validate_safe_cli_token(handle, "handle")
        return await self._run_json(["add", clean_handle], timeout_s=self.subprocess_grace_s)

    async def invite(
        self,
        handle: str | None = None,
        *,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Create or reuse an active mp2 party room and optionally ring ``@handle``."""
        args = ["invite"]
        if handle is not None and handle.strip():
            args.append(_validate_safe_cli_token(handle, "handle"))
        if name is not None and name.strip():
            args.extend(["--name", _validate_safe_cli_token(name, "name")])
        return await self._run_json(args, timeout_s=self.subprocess_grace_s)

    async def join(
        self,
        target: str | None = None,
        *,
        agent_name: str | None = None,
    ) -> dict[str, Any]:
        """Join an mp2 party by #fragment invite URL, @handle, room code, or accept latest invite."""
        args = ["join"]
        if target is not None and target.strip():
            args.append(_validate_safe_cli_token(target, "target"))
        if agent_name is not None and agent_name.strip():
            args.extend(["--agent-name", _validate_safe_cli_token(agent_name, "agent_name")])
        return await self._run_json(args, timeout_s=self.subprocess_grace_s)

    async def leave(self, party_id: int | None = None) -> dict[str, Any]:
        """Leave the active party room (or an explicit ``party_id``)."""
        args = ["leave"]
        if party_id is not None:
            args.append(str(_validate_safe_id(party_id, "party_id")))
        return await self._run_json(args, timeout_s=self.subprocess_grace_s)

    async def send_message(
        self,
        party_id: int,
        body: str,
        *,
        room_scope: str = "party/main",
        target_device_id: int | None = None,
    ) -> dict[str, Any]:
        """Send an outbound party chat message after strict pre-exec secret refusal."""
        pid = _validate_safe_id(party_id, "party_id")
        if not isinstance(body, str) or not body:
            raise ValueError("body must be a non-empty string")
        if not isinstance(room_scope, str) or not room_scope:
            raise ValueError("room_scope must be a non-empty string")
        if body.strip() in _AMBIGUOUS_SAY_FLAGS:
            raise ValueError("body cannot be a bare CLI option flag")

        # Fail closed BEFORE spawning any subprocess so secrets never enter argv.
        refuse_secrets(body)
        refuse_secrets(room_scope)

        args = ["party", "say", str(pid), "--scope", room_scope]
        if target_device_id is not None:
            tdid = _validate_safe_id(target_device_id, "target_device_id")
            args.extend(["--to-device", str(tdid)])
        args.append(body)
        return await self._run_json(args, timeout_s=self.subprocess_grace_s)

    async def post_card(
        self,
        party_id: int,
        title: str,
        summary: str,
        *,
        status: str | None = None,
        diff_stat: str | None = None,
        files: list[str] | None = None,
        agent_name: str | None = None,
    ) -> dict[str, Any]:
        """Post a structured `agent_card` (<=2048 B JSON) via `board post --payload-stdin`."""
        pid = _validate_safe_id(party_id, "party_id")
        clean_title = title.strip()
        clean_summary = summary.strip()
        if not clean_title or not clean_summary:
            raise ValueError("title and summary must be non-empty")
        refuse_secrets(clean_title)
        refuse_secrets(clean_summary)
        card: dict[str, Any] = {"title": clean_title, "summary": clean_summary}
        if status is not None:
            if status not in ("done", "working", "testing", "blocked", "error"):
                raise ValueError("status must be one of done|working|testing|blocked|error")
            card["status"] = status
        if diff_stat and diff_stat.strip():
            refuse_secrets(diff_stat)
            card["diff_stat"] = diff_stat.strip()
        if agent_name and agent_name.strip():
            refuse_secrets(agent_name)
            card["agent_name"] = agent_name.strip()
        if files:
            if len(files) > 16:
                raise ValueError("files exceeds max count of 16")
            for f in files:
                refuse_secrets(f)
            card["files"] = list(files)
        encoded = json.dumps(card, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 2048:
            raise ValueError(f"agent_card JSON exceeds 2048 bytes ({len(encoded)} bytes)")
        return await self._run_json(
            ["board", "post", str(pid), "--scope", "party/main", "--payload-stdin"],
            timeout_s=self.subprocess_grace_s,
            stdin_bytes=encoded,
        )

    async def inbox_send(
        self,
        recipient: str,
        body: str,
        *,
        ttl_secs: int | None = None,
    ) -> dict[str, Any]:
        """Send an async E2EE dead-drop inbox message via stdin (zero secret on argv)."""
        clean_recipient = _validate_safe_cli_token(recipient, "recipient")
        if not isinstance(body, str) or not body:
            raise ValueError("body must be a non-empty string")
        refuse_secrets(body)
        args = ["inbox", "send", clean_recipient, "--stdin"]
        if ttl_secs is not None:
            ttl = int(ttl_secs)
            if ttl < 300 or ttl > 604_800:
                raise ValueError("ttl_secs must be in 300..=604800")
            args.extend(["--ttl-secs", str(ttl)])
        return await self._run_json(
            args,
            timeout_s=self.subprocess_grace_s,
            stdin_bytes=body.encode("utf-8"),
        )

    async def inbox_read(self, *, ack: bool = False) -> dict[str, Any]:
        """Fetch and locally decrypt pending E2EE dead-drop inbox messages, fencing bodies."""
        args = ["inbox", "read"]
        if ack:
            args.append("--ack")
        resp = await self._run_json(args, timeout_s=self.subprocess_grace_s)
        drops = resp.get("drops")
        if isinstance(drops, list):
            fenced_drops: list[dict[str, Any]] = []
            for drop in drops:
                if not isinstance(drop, dict):
                    continue
                body = str(drop.get("body", ""))
                fenced_body, nonce = fence_peer_text(body)
                item = dict(drop)
                item["sender_handle"] = sanitize_peer_text(str(drop.get("sender_handle", "")))
                item["fenced_body"] = fenced_body
                item["nonce"] = nonce
                item["untrusted_remote"] = True
                item.pop("body", None)
                fenced_drops.append(item)
            resp = dict(resp)
            resp["drops"] = fenced_drops
        return resp

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: str | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """BasePlatformAdapter-compatible send method (`chat_id` is party_id string)."""
        _ = reply_to
        meta = metadata or {}
        party_id = int(chat_id)
        room_scope = str(kwargs.get("room_scope", meta.get("room_scope", "party/main")))
        target_device_id = kwargs.get("target_device_id", meta.get("target_device_id"))
        try:
            result = await self.send_message(
                party_id,
                content,
                room_scope=room_scope,
                target_device_id=int(target_device_id) if target_device_id is not None else None,
            )
            delivered_to = result.get("delivered_to")
            withheld = result.get("withheld_unpinned") or []
            disconnected = result.get("disconnected") or []
            undelivered = (
                isinstance(delivered_to, list)
                and len(delivered_to) == 0
                and (len(withheld) > 0 or len(disconnected) > 0)
            )
            if self._hermes_native_mode and _HermesSendResult is not None:
                if undelivered:
                    return _HermesSendResult(
                        success=False,
                        error=(
                            f"message not delivered (withheld_unpinned={len(withheld)}, "
                            f"disconnected={len(disconnected)})"
                        ),
                        raw_response=result,
                    )
                return _HermesSendResult(
                    success=True,
                    message_id=str(result.get("client_msg_id") or result.get("event_seq") or ""),
                    raw_response=result,
                )
            return result
        except Exception as exc:
            if self._hermes_native_mode and _HermesSendResult is not None:
                return _HermesSendResult(success=False, error=redact_url_fragments(str(exc)))
            raise

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        """Hermes BasePlatformAdapter abstract method implementation."""
        return {"name": f"multiplayer/party/{chat_id}", "type": "group"}

    @staticmethod
    def format_inbound_event(party_id: int, raw_event: dict[str, Any]) -> FencedPeerMessage:
        """Convert a raw mp-outpost JSON event into a provenance-fenced message."""
        kind = str(raw_event.get("kind", "unknown"))
        event_seq = int(raw_event.get("event_seq", raw_event.get("seq", 0)))
        sender_client = sanitize_peer_text(
            str(raw_event.get("sender_client", raw_event.get("client", "")))
        )
        is_browser = bool(raw_event.get("is_browser", False)) or sender_client.strip().lower() in (
            "web",
            "browser",
        )
        is_historical_catchup = bool(raw_event.get("is_historical_catchup", False))
        # Browser-originated messages are ALWAYS untrusted remote input even under own handle.
        untrusted_remote = (
            True
            if is_browser
            else bool(raw_event.get("untrusted_remote", kind not in ("membership_changed", "system")))
        )
        provenance = PeerProvenance(
            party_id=party_id,
            event_seq=event_seq,
            kind=kind,
            sender_account_id=int(raw_event.get("sender_account_id", 0)),
            sender_device_id=int(raw_event.get("sender_device_id", 0)),
            sender_handle=sanitize_single_line(str(raw_event.get("sender_handle", raw_event.get("from", "")))),
            safety_number=sanitize_single_line(str(raw_event.get("safety_number", ""))),
            room_scope=sanitize_single_line(str(raw_event.get("room_scope", ""))),
            party_epoch=int(raw_event.get("party_epoch", 0)),
            untrusted_remote=untrusted_remote,
            is_browser=is_browser,
            sender_client=sender_client,
            is_historical_catchup=is_historical_catchup,
        )

        if kind in ("chat_message", "chat"):
            payload_raw = str(raw_event.get("body", ""))
        elif kind == "agent_card":
            if raw_event.get("body") is not None:
                body_val = raw_event["body"]
                card_text = body_val if isinstance(body_val, str) else json.dumps(body_val, sort_keys=True)
            elif raw_event.get("card") is not None:
                card_val = raw_event["card"]
                card_text = card_val if isinstance(card_val, str) else json.dumps(card_val, sort_keys=True)
            else:
                card_text = json.dumps(raw_event, sort_keys=True)
            payload_raw = (
                f"scope: {provenance.room_scope}\n{card_text}"
                if provenance.room_scope
                else card_text
            )
        elif kind == "control_notice":
            payload_raw = str(raw_event.get("text", ""))
        elif kind == "bridge_envelope":
            raw_b64 = str(raw_event.get("payload_b64", ""))
            card_rendered: str | None = None
            if raw_b64:
                with contextlib.suppress(Exception):
                    decoded = base64.b64decode(raw_b64, validate=True).decode("utf-8")
                    parsed_card = json.loads(decoded)
                    if (
                        isinstance(parsed_card, dict)
                        and isinstance(parsed_card.get("title"), str)
                        and isinstance(parsed_card.get("summary"), str)
                    ):
                        card_rendered = json.dumps(parsed_card, sort_keys=True)
            if card_rendered is not None:
                payload_raw = (
                    f"scope: {provenance.room_scope}\nagent_card: {card_rendered}"
                    if provenance.room_scope
                    else f"agent_card: {card_rendered}"
                )
            else:
                payload_raw = f"scope: {provenance.room_scope}\npayload_b64: {raw_b64}"
        elif kind in ("membership_changed", "system"):
            payload_raw = str(raw_event.get("summary") or raw_event.get("body") or "")
        else:
            payload_raw = json.dumps(raw_event, sort_keys=True)

        fenced_body, nonce = fence_peer_text(payload_raw)
        return FencedPeerMessage(
            provenance=provenance,
            fenced_body=fenced_body,
            nonce=nonce,
            raw_kind=kind,
        )

    async def wait_once(
        self,
        *,
        party_id: int | None = None,
        timeout_ms: int | None = None,
    ) -> tuple[list[FencedPeerMessage], dict[str, Any]]:
        """Execute a single bounded ``mp-outpost --json party wait`` call and update cursor."""
        pid = party_id or (self.cursor.party_id if self.cursor else self.party_id)
        if pid is None:
            listed = await self.list_parties()
            parties = listed.get("parties") or []
            if not parties:
                return [], {"timed_out": True, "events": []}
            pid = int(parties[0]["party_id"])
            self.party_id = pid

        pid = _validate_safe_id(pid, "party_id")
        if self.cursor is None or self.cursor.party_id != pid:
            self.cursor = PartyCursor(party_id=pid)

        clamped_ms = clamp_wait_timeout_ms(
            self.wait_timeout_ms if timeout_ms is None else timeout_ms
        )
        args = [
            "party",
            "wait",
            str(pid),
            "--after-seq",
            str(self.cursor.after_seq),
            "--timeout-ms",
            str(clamped_ms),
        ]
        if self.cursor.daemon_epoch > 0:
            args.extend(["--cursor-epoch", str(self.cursor.daemon_epoch)])

        wall_budget_s = (clamped_ms / 1000.0) + self.subprocess_grace_s
        resp = await self._run_json(args, timeout_s=wall_budget_s)

        if resp.get("cursor_reset"):
            self.cursor.cursor_reset_count += 1
        if resp.get("gap_possible"):
            self.cursor.gap_possible_count += 1

        new_epoch = int(resp.get("daemon_epoch", self.cursor.daemon_epoch))
        if new_epoch > 0:
            self.cursor.daemon_epoch = new_epoch

        events_raw = resp.get("events") or []
        fenced_messages: list[FencedPeerMessage] = []
        max_seq = self.cursor.after_seq
        for ev in events_raw:
            if not isinstance(ev, dict):
                continue
            msg = self.format_inbound_event(pid, ev)
            fenced_messages.append(msg)
            if msg.provenance.event_seq > max_seq:
                max_seq = msg.provenance.event_seq

        if "next_seq" in resp and resp["next_seq"] is not None:
            next_seq = int(resp["next_seq"])
            if resp.get("cursor_reset"):
                self.cursor.after_seq = next_seq
            else:
                self.cursor.after_seq = max(max_seq, next_seq)
        else:
            self.cursor.after_seq = max_seq

        return fenced_messages, resp

    async def _dispatch_message(self, msg: FencedPeerMessage) -> None:
        # Filter own-device echoes so gateway sessions never loop on their own sends.
        if (
            self._own_device_id > 0
            and msg.provenance.sender_device_id == self._own_device_id
        ):
            return
        if self.on_message is not None:
            result = self.on_message(msg)
            if asyncio.iscoroutine(result):
                await result
            return
        if (
            self._hermes_native_mode
            and _HermesMessageEvent is not None
            and _HermesMessageType is not None
            and getattr(self, "_message_handler", None) is not None
        ):
            origin = " origin=browser" if msg.provenance.is_browser else ""
            meta = (
                f"[party={msg.provenance.party_id} seq={msg.provenance.event_seq} "
                f"kind={msg.provenance.kind} from={msg.provenance.sender_handle}"
                f"({msg.provenance.sender_account_id}){origin}]"
            )
            source = self.build_source(
                chat_id=str(msg.provenance.party_id),
                chat_name=f"Party #{msg.provenance.party_id}",
                chat_type="group",
                user_id=str(msg.provenance.sender_account_id or msg.provenance.sender_device_id),
                user_name=msg.provenance.sender_handle or "peer",
            )
            event = _HermesMessageEvent(
                text=f"{meta}\n{msg.fenced_body}",
                message_type=_HermesMessageType.TEXT,
                source=source,
                raw_message={
                    "party_id": msg.provenance.party_id,
                    "event_seq": msg.provenance.event_seq,
                    "kind": msg.provenance.kind,
                    "is_browser": msg.provenance.is_browser,
                },
                message_id=f"mp-{msg.provenance.party_id}-{msg.provenance.event_seq}",
            )
            await self.handle_message(event)

    async def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                messages, _resp = await self.wait_once()
                self.consecutive_errors = 0
                self.last_error = None
                for msg in messages:
                    if self._stop_event.is_set():
                        break
                    await self._dispatch_message(msg)
            except asyncio.CancelledError:
                break
            except OutpostEofError as exc:
                self.last_error = str(exc)
                self.consecutive_errors += 1
                LOGGER.warning("mp-outpost EOF during party_wait: %s", exc)
                if self.stop_on_eof or self.consecutive_errors >= self.max_consecutive_errors:
                    self._stop_event.set()
                    break
                await self._sleep_cancelable(self.backoff_s)
            except OutpostError as exc:
                self.last_error = str(exc)
                self.consecutive_errors += 1
                LOGGER.warning("mp-outpost error during party_wait: %s", exc)
                if self.consecutive_errors >= self.max_consecutive_errors:
                    self._stop_event.set()
                    break
                await self._sleep_cancelable(self.backoff_s)

    async def _sleep_cancelable(self, delay_s: float) -> None:
        if delay_s <= 0:
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stop_event.wait(), timeout=delay_s)

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        """Hermes BasePlatformAdapter connect entry point."""
        _ = is_reconnect
        with contextlib.suppress(Exception):
            st = await self.status()
            dev_id = st.get("device_id")
            if isinstance(dev_id, int) and dev_id > 0:
                self._own_device_id = dev_id
        await self.start()
        if hasattr(self, "_mark_connected"):
            self._mark_connected()
        else:
            self._running = True
        return True

    async def disconnect(self) -> None:
        """Hermes BasePlatformAdapter disconnect entry point."""
        await self.stop()
        if hasattr(self, "_mark_disconnected"):
            self._mark_disconnected()
        else:
            self._running = False

    async def start(self) -> None:
        """Start the background party_wait polling loop."""
        if self._loop_task is not None and not self._loop_task.done():
            return
        self._stop_event.clear()
        self._loop_task = asyncio.create_task(self._poll_loop(), name="multiplayer-party-wait")

    async def stop(self) -> None:
        """Gracefully stop polling and terminate any active mp-outpost child process."""
        self._stop_event.set()
        procs = list(self._active_procs)
        for proc in procs:
            await self._terminate_proc(proc)
        if self._loop_task is not None:
            self._loop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._loop_task
            self._loop_task = None

    @property
    def running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()


__all__ = [
    "BasePlatformAdapter",
    "DEFAULT_PARTY_WAIT_MS",
    "DEFAULT_SUBPROCESS_GRACE_S",
    "FencedPeerMessage",
    "MAX_PARTY_WAIT_MS",
    "MAX_SAFE_ID",
    "MultiplayerPlatformAdapter",
    "OutpostEofError",
    "OutpostError",
    "OutpostTimeoutError",
    "PartyCursor",
    "PeerProvenance",
    "SecretRefusalError",
    "clamp_wait_timeout_ms",
]
