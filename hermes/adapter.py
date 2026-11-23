"""Tier 3 Hermes Gateway Platform Adapter wrapping mp-outpost CLI/daemon IPC."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Final

from .security import SecretRefusalError, fence_peer_text, refuse_secrets, sanitize_peer_text

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

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = dict(config or {})

    async def start(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    async def stop(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    async def send(self, target: str, text: str, **kwargs: Any) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


def _resolve_base_adapter() -> type:
    for mod_path in (
        "hermes_agent.gateway.platforms.base",
        "gateway.platforms.base",
        "hermes.gateway.platforms.base",
    ):
        try:
            mod = __import__(mod_path, fromlist=["BasePlatformAdapter"])
            base = getattr(mod, "BasePlatformAdapter", None)
            if isinstance(base, type):
                return base
        except ImportError:
            continue
    return _StandaloneBasePlatformAdapter


BasePlatformAdapter: type = _resolve_base_adapter()


class OutpostError(RuntimeError):
    """Base error raised by mp-outpost CLI invocations."""


class OutpostTimeoutError(OutpostError):
    """Raised when an mp-outpost subprocess exceeds its bounded wall-clock budget."""


class OutpostEofError(OutpostError):
    """Raised when mp-outpost terminates abruptly with EOF / empty output."""


@dataclass(frozen=True)
class PeerProvenance:
    """Cryptographically verified sender metadata resolved by mp-outpost daemon."""

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


class MultiplayerPlatformAdapter(BasePlatformAdapter):  # type: ignore[misc]
    """Hermes Gateway platform adapter for multiplayer.tech via ``mp-outpost``.

    Security invariants:
    - Never reads ``root.key``, ``.mpkey``, ``device_secret``, or ``~/.hermes/.env``.
    - Refuses outbound secrets BEFORE spawning ``mp-outpost`` (secrets never enter argv).
    - Wraps every inbound remote peer payload in a fresh per-message CSPRNG nonce fence.
    - Enforces bounded timeouts and clean ``SIGTERM``/``SIGKILL`` child shutdown.
    """

    platform_name: str = "multiplayer"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
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
        super().__init__(config or {})
        cfg = config or {}
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
    ) -> dict[str, Any]:
        argv = self._base_argv() + sub_args
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._active_procs.add(proc)
        try:
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
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
        stderr_text = stderr_b.decode("utf-8", errors="replace").strip()

        if not stdout_text:
            if proc.returncode in (0, None):
                raise OutpostEofError("mp-outpost closed stdout without a JSON response (EOF)")
            raise OutpostEofError(
                f"mp-outpost exited with code {proc.returncode} and empty stdout: {stderr_text[:200]}"
            )

        if proc.returncode != 0:
            raise OutpostError(
                f"mp-outpost exited with code {proc.returncode}: {stderr_text[:200] or stdout_text[:200]}"
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
        return await self._run_json(["friend", "list"], timeout_s=self.subprocess_grace_s)

    async def send_message(
        self,
        party_id: int,
        body: str,
        *,
        room_scope: str = "party/main",
        target_device_id: int | None = None,
    ) -> dict[str, Any]:
        """Send an outbound P2P chat message after strict pre-exec secret refusal."""
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

    async def send(self, target: str, text: str, **kwargs: Any) -> dict[str, Any]:
        """BasePlatformAdapter-compatible send method (`target` is party_id string)."""
        party_id = int(target)
        room_scope = str(kwargs.get("room_scope", "party/main"))
        target_device_id = kwargs.get("target_device_id")
        return await self.send_message(
            party_id,
            text,
            room_scope=room_scope,
            target_device_id=int(target_device_id) if target_device_id is not None else None,
        )

    @staticmethod
    def format_inbound_event(party_id: int, raw_event: dict[str, Any]) -> FencedPeerMessage:
        """Convert a raw mp-outpost JSON event into a provenance-fenced message."""
        kind = str(raw_event.get("kind", "unknown"))
        event_seq = int(raw_event.get("event_seq", 0))
        provenance = PeerProvenance(
            party_id=party_id,
            event_seq=event_seq,
            kind=kind,
            sender_account_id=int(raw_event.get("sender_account_id", 0)),
            sender_device_id=int(raw_event.get("sender_device_id", 0)),
            sender_handle=sanitize_peer_text(str(raw_event.get("sender_handle", ""))),
            safety_number=sanitize_peer_text(str(raw_event.get("safety_number", ""))),
            room_scope=sanitize_peer_text(str(raw_event.get("room_scope", ""))),
            party_epoch=int(raw_event.get("party_epoch", 0)),
            untrusted_remote=bool(raw_event.get("untrusted_remote", kind != "membership_changed")),
        )

        if kind == "chat_message":
            payload_raw = str(raw_event.get("body", ""))
        elif kind == "control_notice":
            payload_raw = str(raw_event.get("text", ""))
        elif kind == "bridge_envelope":
            payload_raw = f"scope: {provenance.room_scope}\npayload_b64: {raw_event.get('payload_b64', '')}"
        elif kind == "membership_changed":
            payload_raw = str(raw_event.get("summary", ""))
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
        if self.on_message is None:
            return
        result = self.on_message(msg)
        if asyncio.iscoroutine(result):
            await result

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
    "MultiplayerPlatformAdapter",
    "OutpostEofError",
    "OutpostError",
    "OutpostTimeoutError",
    "PartyCursor",
    "PeerProvenance",
    "SecretRefusalError",
    "clamp_wait_timeout_ms",
]
