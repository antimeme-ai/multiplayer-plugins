"""Nous Research Hermes Agent plugin for multiplayer.tech (`mp-outpost`).

Implements all three integration tiers:
- Tier 1: MCP config snippet generator & atomic ``~/.hermes/config.yaml`` upserter
  (``timeout: 90``, ``connect_timeout: 30`` for ``party_wait`` max 45 s).
- Tier 2: ``hermes multiplayer`` CLI commands (``setup``, ``status``, ``doctor``,
  ``parties``, ``friends``) and non-blocking ``pre_llm_call`` unread-message hook.
- Tier 3: ``MultiplayerPlatformAdapter`` Gateway platform adapter registered via
  ``ctx.register_platform("multiplayer", MultiplayerPlatformAdapter)``.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Final

import yaml

from .adapter import (
    BasePlatformAdapter,
    FencedPeerMessage,
    MultiplayerPlatformAdapter,
    OutpostEofError,
    OutpostError,
    OutpostTimeoutError,
    PartyCursor,
    PeerProvenance,
    clamp_wait_timeout_ms,
)
from .security import (
    SecretRefusalError,
    break_angle_runs,
    detect_secret_kind,
    fence_peer_text,
    refuse_secrets,
    sanitize_peer_text,
)

PLUGIN_NAME: Final[str] = "multiplayer-outpost"
PLUGIN_VERSION: Final[str] = "0.3.0"
DEFAULT_HERMES_MCP_TIMEOUT_S: Final[int] = 90
DEFAULT_HERMES_CONNECT_TIMEOUT_S: Final[int] = 30
MIN_PARTY_WAIT_TOOL_TIMEOUT_S: Final[int] = 60

CommandRunner = Callable[[list[str], float], subprocess.CompletedProcess[str]]


def default_hermes_config_path() -> Path:
    return Path.home() / ".hermes" / "config.yaml"


def build_hermes_mcp_entry(
    *,
    binary: str = "mp-outpost",
    state_dir: str | None = None,
    timeout: int = DEFAULT_HERMES_MCP_TIMEOUT_S,
    connect_timeout: int = DEFAULT_HERMES_CONNECT_TIMEOUT_S,
) -> dict[str, Any]:
    """Build the Hermes ``mcp_servers.multiplayer`` mapping."""
    if not binary or not binary.strip():
        raise ValueError("binary must be a non-empty command or path")
    if timeout < MIN_PARTY_WAIT_TOOL_TIMEOUT_S:
        raise ValueError(
            f"timeout must be >= {MIN_PARTY_WAIT_TOOL_TIMEOUT_S}s to avoid premature party_wait timeouts"
        )
    if connect_timeout < 5:
        raise ValueError("connect_timeout must be >= 5s")

    entry: dict[str, Any] = {
        "command": binary,
        "args": ["mcp"],
        "timeout": int(timeout),
        "connect_timeout": int(connect_timeout),
    }
    if state_dir:
        entry["env"] = {"OUTPOST_STATE_DIR": state_dir}
    return entry


def render_hermes_mcp_snippet(
    *,
    binary: str = "mp-outpost",
    state_dir: str | None = None,
    timeout: int = DEFAULT_HERMES_MCP_TIMEOUT_S,
    connect_timeout: int = DEFAULT_HERMES_CONNECT_TIMEOUT_S,
) -> str:
    """Render a copy-pasteable ``~/.hermes/config.yaml`` snippet."""
    payload = {
        "mcp_servers": {
            "multiplayer": build_hermes_mcp_entry(
                binary=binary,
                state_dir=state_dir,
                timeout=timeout,
                connect_timeout=connect_timeout,
            )
        }
    }
    return yaml.safe_dump(payload, sort_keys=False)


def upsert_hermes_mcp_config(
    config_path: str | Path | None = None,
    *,
    binary: str = "mp-outpost",
    state_dir: str | None = None,
    timeout: int = DEFAULT_HERMES_MCP_TIMEOUT_S,
    connect_timeout: int = DEFAULT_HERMES_CONNECT_TIMEOUT_S,
) -> dict[str, Any]:
    """Atomically upsert ``mcp_servers.multiplayer`` in ``~/.hermes/config.yaml``.

    Creates a ``.bak`` backup when updating an existing file and writes through a
    same-directory temporary file + ``os.replace`` so partial writes cannot corrupt
    Hermes configuration. Never touches ``~/.hermes/.env`` or private keys.
    """
    target = Path(config_path) if config_path is not None else default_hermes_config_path()
    if target.is_symlink():
        raise ValueError(f"refusing to overwrite symlinked Hermes config: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any] = {}
    backup_path: Path | None = None
    if target.exists():
        raw_text = target.read_text(encoding="utf-8")
        loaded = yaml.safe_load(raw_text) if raw_text.strip() else {}
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Hermes config at {target} must be a YAML mapping")
        existing = loaded
        backup_path = target.with_suffix(target.suffix + ".bak")
        if backup_path.is_symlink():
            raise ValueError(f"refusing to overwrite symlinked backup file: {backup_path}")
        bak_fd, bak_tmp = tempfile.mkstemp(prefix=".backup-", suffix=".yaml.bak.tmp", dir=str(target.parent))
        try:
            with os.fdopen(bak_fd, "w", encoding="utf-8") as bfh:
                bfh.write(raw_text)
                bfh.flush()
                os.fsync(bfh.fileno())
            os.chmod(bak_tmp, 0o600)
            os.replace(bak_tmp, backup_path)
        except Exception:
            if os.path.exists(bak_tmp):
                os.unlink(bak_tmp)
            raise

    mcp_servers = existing.get("mcp_servers")
    if mcp_servers is None:
        mcp_servers = {}
        existing["mcp_servers"] = mcp_servers
    if not isinstance(mcp_servers, dict):
        raise ValueError("top-level 'mcp_servers' in Hermes config must be a YAML mapping")

    entry = build_hermes_mcp_entry(
        binary=binary,
        state_dir=state_dir,
        timeout=timeout,
        connect_timeout=connect_timeout,
    )
    mcp_servers["multiplayer"] = entry

    rendered = yaml.safe_dump(existing, sort_keys=False)
    fd, tmp_name = tempfile.mkstemp(prefix=".config-", suffix=".yaml.tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(rendered)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    return {
        "config_path": str(target),
        "backup_path": str(backup_path) if backup_path is not None else None,
        "entry": entry,
    }


def _default_sync_runner(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )


class UnreadNotificationHook:
    """Non-blocking ``pre_llm_call`` hook checking for unread party messages."""

    def __init__(
        self,
        *,
        binary: str = "mp-outpost",
        state_dir: str | None = None,
        party_id: int | None = None,
        limit: int = 10,
        timeout_s: float = 2.0,
        runner: CommandRunner | None = None,
    ) -> None:
        self.binary = binary
        self.state_dir = state_dir
        self.party_id = party_id
        self.limit = max(1, min(int(limit), 100))
        self.timeout_s = max(0.1, float(timeout_s))
        self._runner = runner or _default_sync_runner
        self.cursor: PartyCursor | None = PartyCursor(party_id=party_id) if party_id else None

    def _argv(self, sub_args: list[str]) -> list[str]:
        base = [self.binary]
        if self.state_dir:
            base.extend(["--state-dir", self.state_dir])
        base.append("--json")
        return base + sub_args

    def _run_json_quiet(self, sub_args: list[str]) -> dict[str, Any] | None:
        try:
            proc = self._runner(self._argv(sub_args), self.timeout_s)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def __call__(self, *_args: Any, **_kwargs: Any) -> dict[str, Any] | None:
        pid = self.cursor.party_id if self.cursor else self.party_id
        if pid is None:
            listed = self._run_json_quiet(["party", "list"])
            if not listed:
                return None
            parties = listed.get("parties") or []
            if not parties:
                return None
            pid = int(parties[0]["party_id"])
            self.party_id = pid
            self.cursor = PartyCursor(party_id=pid)
        elif self.cursor is None:
            self.cursor = PartyCursor(party_id=pid)

        poll_args = [
            "party",
            "read",
            str(pid),
            "--after-seq",
            str(self.cursor.after_seq),
            "--limit",
            str(self.limit),
        ]
        if self.cursor.daemon_epoch > 0:
            poll_args.extend(["--cursor-epoch", str(self.cursor.daemon_epoch)])

        resp = self._run_json_quiet(poll_args)
        if not resp:
            return None

        new_epoch = int(resp.get("daemon_epoch", self.cursor.daemon_epoch))
        if new_epoch > 0:
            self.cursor.daemon_epoch = new_epoch
        if resp.get("cursor_reset"):
            self.cursor.cursor_reset_count += 1
        if resp.get("gap_possible"):
            self.cursor.gap_possible_count += 1

        events_raw = resp.get("events") or []
        fenced_items: list[dict[str, Any]] = []
        max_seq = self.cursor.after_seq
        for ev in events_raw:
            if not isinstance(ev, dict):
                continue
            msg = MultiplayerPlatformAdapter.format_inbound_event(pid, ev)
            if msg.provenance.event_seq > max_seq:
                max_seq = msg.provenance.event_seq
            fenced_items.append(
                {
                    "event_seq": msg.provenance.event_seq,
                    "kind": msg.provenance.kind,
                    "sender_account_id": msg.provenance.sender_account_id,
                    "sender_handle": msg.provenance.sender_handle,
                    "safety_number": msg.provenance.safety_number,
                    "untrusted_remote": msg.provenance.untrusted_remote,
                    "fenced_body": msg.fenced_body,
                }
            )

        if "next_seq" in resp and resp["next_seq"] is not None:
            next_seq = int(resp["next_seq"])
            self.cursor.after_seq = next_seq if resp.get("cursor_reset") else max(max_seq, next_seq)
        else:
            self.cursor.after_seq = max_seq

        if not fenced_items:
            return None

        return {
            "source": "multiplayer-outpost",
            "party_id": pid,
            "unread_count": len(fenced_items),
            "cursor_reset": bool(resp.get("cursor_reset", False)),
            "gap_possible": bool(resp.get("gap_possible", False)),
            "messages": fenced_items,
        }


def handle_cli_command(
    args: Any,
    *,
    config_path: str | Path | None = None,
    binary: str = "mp-outpost",
    runner: CommandRunner | None = None,
) -> tuple[int, str]:
    """Handle ``hermes multiplayer <subcommand>`` CLI invocations."""
    action = getattr(args, "action", None) or "status"
    bin_path = getattr(args, "binary", None) or binary
    state_dir = getattr(args, "state_dir", None)
    cfg_path = getattr(args, "config", None) or config_path
    run_cmd = runner or _default_sync_runner

    if action == "setup":
        timeout = int(getattr(args, "timeout", DEFAULT_HERMES_MCP_TIMEOUT_S))
        connect_timeout = int(getattr(args, "connect_timeout", DEFAULT_HERMES_CONNECT_TIMEOUT_S))
        if getattr(args, "write", False):
            result = upsert_hermes_mcp_config(
                cfg_path,
                binary=bin_path,
                state_dir=state_dir,
                timeout=timeout,
                connect_timeout=connect_timeout,
            )
            return (
                0,
                f"Updated {result['config_path']} with mcp_servers.multiplayer "
                f"(timeout={timeout}s, connect_timeout={connect_timeout}s). "
                "Run /reload-mcp in active Hermes sessions.",
            )
        snippet = render_hermes_mcp_snippet(
            binary=bin_path,
            state_dir=state_dir,
            timeout=timeout,
            connect_timeout=connect_timeout,
        )
        return (
            0,
            "# Add to ~/.hermes/config.yaml (or re-run with --write), then run /reload-mcp:\n"
            + snippet,
        )

    sub_map: dict[str, list[str]] = {
        "status": ["party", "status"],
        "doctor": ["doctor"],
        "parties": ["party", "list"],
        "friends": ["friend", "list"],
    }
    if action not in sub_map:
        return (2, f"Unknown subcommand '{action}'. Expected one of: setup, status, doctor, parties, friends.")

    argv = [bin_path]
    if state_dir:
        argv.extend(["--state-dir", state_dir])
    if getattr(args, "json", False):
        argv.append("--json")
    argv.extend(sub_map[action])

    try:
        proc = run_cmd(argv, 15.0)
    except FileNotFoundError:
        return (127, f"mp-outpost binary '{bin_path}' not found on PATH.")
    except subprocess.TimeoutExpired:
        return (124, f"mp-outpost {' '.join(sub_map[action])} timed out.")

    output = (proc.stdout or proc.stderr or "").strip()
    return (proc.returncode, output)


def _setup_cli_parser(subparser: Any) -> None:
    subparser.add_argument(
        "action",
        nargs="?",
        default="status",
        choices=["setup", "status", "doctor", "parties", "friends"],
        help="Subcommand to execute (default: status).",
    )
    subparser.add_argument("--write", action="store_true", help="Write ~/.hermes/config.yaml during setup.")
    subparser.add_argument("--config", default=None, help="Override Hermes config.yaml path.")
    subparser.add_argument("--binary", default="mp-outpost", help="Path to mp-outpost binary.")
    subparser.add_argument("--state-dir", default=None, help="Optional OUTPOST_STATE_DIR override.")
    subparser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_HERMES_MCP_TIMEOUT_S,
        help="Per-tool MCP timeout in seconds (default: 90, min: 60).",
    )
    subparser.add_argument(
        "--connect-timeout",
        type=int,
        default=DEFAULT_HERMES_CONNECT_TIMEOUT_S,
        help="MCP handshake connect_timeout in seconds (default: 30).",
    )
    subparser.add_argument("--json", action="store_true", help="Emit JSON output from mp-outpost.")


def register(ctx: Any) -> dict[str, Any]:
    """Hermes Agent plugin entry point wiring Tier 1, Tier 2, and Tier 3 capabilities."""
    registered: dict[str, Any] = {
        "plugin": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "hooks": [],
        "cli": [],
        "platforms": [],
        "skills": [],
    }

    unread_hook = UnreadNotificationHook()
    if hasattr(ctx, "register_hook"):
        ctx.register_hook("pre_llm_call", unread_hook)
        registered["hooks"].append("pre_llm_call")

    if hasattr(ctx, "register_cli_command"):
        ctx.register_cli_command(
            "multiplayer",
            "Configure and inspect multiplayer.tech mp-outpost MCP & E2EE P2P parties",
            _setup_cli_parser,
            handle_cli_command,
        )
        registered["cli"].append("multiplayer")

    if hasattr(ctx, "register_platform"):
        ctx.register_platform("multiplayer", MultiplayerPlatformAdapter)
        registered["platforms"].append("multiplayer")

    skill_path = Path(__file__).resolve().parent.parent / "skills" / "multiplayer" / "SKILL.md"
    if hasattr(ctx, "register_skill") and skill_path.is_file():
        ctx.register_skill("multiplayer", str(skill_path))
        registered["skills"].append("multiplayer")

    return registered


__all__ = [
    "BasePlatformAdapter",
    "DEFAULT_HERMES_CONNECT_TIMEOUT_S",
    "DEFAULT_HERMES_MCP_TIMEOUT_S",
    "FencedPeerMessage",
    "MIN_PARTY_WAIT_TOOL_TIMEOUT_S",
    "MultiplayerPlatformAdapter",
    "OutpostEofError",
    "OutpostError",
    "OutpostTimeoutError",
    "PLUGIN_NAME",
    "PLUGIN_VERSION",
    "PartyCursor",
    "PeerProvenance",
    "SecretRefusalError",
    "UnreadNotificationHook",
    "break_angle_runs",
    "build_hermes_mcp_entry",
    "clamp_wait_timeout_ms",
    "default_hermes_config_path",
    "detect_secret_kind",
    "fence_peer_text",
    "handle_cli_command",
    "refuse_secrets",
    "register",
    "render_hermes_mcp_snippet",
    "sanitize_peer_text",
    "upsert_hermes_mcp_config",
]
