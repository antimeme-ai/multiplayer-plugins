"""Detached `phux` and in-place `mp-outpost chat` launcher for Hermes Agent.

Zero external dependencies (Python 3 stdlib only). Refuses secret tokens and
`#fragment` invite URLs before spawning any subprocess (`shell=False`).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from .security import SecretRefusalError, refuse_secrets

DEFAULT_SESSION_NAME = "multiplayer-chat"
_SAFE_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_TARGET_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_session_name(raw: str) -> str:
    cleaned = raw.strip()
    if not _SAFE_SESSION_RE.fullmatch(cleaned):
        raise ValueError(f"invalid session name {raw!r}: use [A-Za-z0-9._-] starting with alphanumeric")
    return cleaned


def validate_chat_target(raw: str | None) -> str | None:
    if raw is None or not raw.strip():
        return None
    cleaned = raw.strip()
    if cleaned.startswith("-"):
        raise ValueError("chat target cannot start with '-'")
    if "#" in cleaned:
        raise ValueError(
            "refused #fragment invite URL on process argv; redeem fragment links directly via `mp-outpost join` in your terminal"
        )
    refuse_secrets(cleaned)
    if not _SAFE_TARGET_RE.fullmatch(cleaned):
        raise ValueError("chat target must be a @handle, room code, or numeric party ID")
    return cleaned


def _extract_pane_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("terminal", "pane", "pane_id", "id"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    for nested_key in ("pane", "terminal", "seed", "result"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            found = _extract_pane_id(nested)
            if found:
                return found
    return None


def launch_detached_chat(
    *,
    target: str | None = None,
    session: str = DEFAULT_SESSION_NAME,
    outpost_binary: str = "mp-outpost",
    state_dir: str | None = None,
    phux_binary: str | None = None,
    tmux_binary: str | None = None,
    omarchy_tui_binary: str | None = None,
    runner: Any = None,
) -> dict[str, Any]:
    """Launch or reuse `mp-outpost chat` in a detached `phux` window (tmux/Omarchy fallback)."""
    session_name = validate_session_name(session)
    clean_target = validate_chat_target(target)
    run_cmd = runner or subprocess.run

    outpost_cmd = [outpost_binary]
    if state_dir:
        outpost_cmd.extend(["--state-dir", state_dir])
    outpost_cmd.append("chat")
    if clean_target is not None:
        outpost_cmd.append(clean_target)

    phux_bin = phux_binary if phux_binary is not None else shutil.which("phux")
    if phux_bin:
        ls_proc = run_cmd(
            [phux_bin, "ls", "--json"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        existing_session: dict[str, Any] | None = None
        if ls_proc.returncode == 0 and ls_proc.stdout.strip():
            try:
                ls_data = json.loads(ls_proc.stdout)
                for sess in ls_data.get("sessions", []):
                    if isinstance(sess, dict) and sess.get("name") == session_name:
                        existing_session = sess
                        break
            except json.JSONDecodeError:
                existing_session = None

        if existing_session is not None:
            exec_info = existing_session.get("exec") or {}
            running_count = int(exec_info.get("running", 0) or 0) + int(exec_info.get("starting", 0) or 0)
            if running_count > 0:
                return {
                    "ok": True,
                    "backend": "phux",
                    "session": session_name,
                    "pane_id": None,
                    "reused": True,
                    "attach_cmd": f"phux attach {session_name}",
                    "native_cmd": f"phux native attach {session_name}:0.0",
                    "message": (
                        f"Party chat is already running in detached phux session '{session_name}'. "
                        f"Grab it with: phux attach {session_name}"
                    ),
                }
            run_cmd(
                [phux_bin, "kill", "--yes", session_name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        new_proc = run_cmd(
            [phux_bin, "new", "--json", "-s", session_name, "--", *outpost_cmd],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if new_proc.returncode == 0:
            pane_id: str | None = None
            if new_proc.stdout.strip():
                try:
                    pane_id = _extract_pane_id(json.loads(new_proc.stdout))
                except json.JSONDecodeError:
                    pane_id = None
            native_target = pane_id or f"{session_name}:0.0"
            return {
                "ok": True,
                "backend": "phux",
                "session": session_name,
                "pane_id": pane_id,
                "reused": False,
                "attach_cmd": f"phux attach {session_name}",
                "native_cmd": f"phux native attach {native_target}",
                "message": (
                    f"Started detached phux party chat in session '{session_name}'"
                    + (f" ({pane_id})" if pane_id else "")
                    + f". Grab it with: phux attach {session_name} (or window: phux native attach {native_target})"
                ),
            }

    tmux_bin = tmux_binary if tmux_binary is not None else shutil.which("tmux")
    if tmux_bin:
        has_proc = run_cmd(
            [tmux_bin, "has-session", "-t", session_name],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if has_proc.returncode == 0:
            return {
                "ok": True,
                "backend": "tmux",
                "session": session_name,
                "pane_id": None,
                "reused": True,
                "attach_cmd": f"tmux attach -t {session_name}",
                "native_cmd": None,
                "message": (
                    f"Party chat is already running in detached tmux session '{session_name}'. "
                    f"Grab it with: tmux attach -t {session_name}"
                ),
            }
        create_proc = run_cmd(
            [tmux_bin, "new-session", "-d", "-s", session_name, "--", *outpost_cmd],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if create_proc.returncode == 0:
            return {
                "ok": True,
                "backend": "tmux",
                "session": session_name,
                "pane_id": None,
                "reused": False,
                "attach_cmd": f"tmux attach -t {session_name}",
                "native_cmd": None,
                "message": (
                    f"Started detached tmux party chat in session '{session_name}'. "
                    f"Grab it with: tmux attach -t {session_name}"
                ),
            }

    omarchy_bin = omarchy_tui_binary if omarchy_tui_binary is not None else shutil.which("omarchy-launch-tui")
    if omarchy_bin:
        subprocess.Popen(
            [omarchy_bin, *outpost_cmd],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {
            "ok": True,
            "backend": "omarchy-launch-tui",
            "session": session_name,
            "pane_id": None,
            "reused": False,
            "attach_cmd": " ".join(outpost_cmd),
            "native_cmd": None,
            "message": "Launched mp-outpost chat in a native Omarchy TUI window.",
        }

    return {
        "ok": False,
        "backend": "manual",
        "session": session_name,
        "pane_id": None,
        "reused": False,
        "attach_cmd": " ".join(outpost_cmd),
        "native_cmd": None,
        "message": (
            "Neither phux, tmux, nor omarchy-launch-tui was found on PATH. "
            f"Run directly in another terminal: {' '.join(outpost_cmd)}"
        ),
    }


def run_chat_in_place(
    *,
    target: str | None = None,
    outpost_binary: str = "mp-outpost",
    state_dir: str | None = None,
) -> int:
    """Run interactive `mp-outpost chat` directly in the current terminal (suspending prompt_toolkit if active)."""
    clean_target = validate_chat_target(target)
    argv = [outpost_binary]
    if state_dir:
        argv.extend(["--state-dir", state_dir])
    argv.append("chat")
    if clean_target is not None:
        argv.append(clean_target)

    def _run() -> int:
        proc = subprocess.run(argv, check=False)
        return int(proc.returncode)

    try:
        from prompt_toolkit.application import get_app_or_none, run_in_terminal

        if get_app_or_none() is not None:
            rc_box: list[int] = [0]

            def _wrapped() -> None:
                rc_box[0] = _run()

            run_in_terminal(_wrapped)
            return rc_box[0]
    except Exception:
        pass
    return _run()


__all__ = [
    "DEFAULT_SESSION_NAME",
    "SecretRefusalError",
    "launch_detached_chat",
    "run_chat_in_place",
    "validate_chat_target",
    "validate_session_name",
]
