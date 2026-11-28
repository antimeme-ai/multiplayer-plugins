#!/usr/bin/env python3
"""Launch `mp-outpost chat` in a detached `phux` window (with tmux / Omarchy fallback).

Zero external dependencies (Python 3 stdlib only). Refuses flag-like targets,
secret tokens, and `#fragment` invite URLs before spawning any subprocess.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_SESSION_NAME = "multiplayer-chat"
SAFE_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SAFE_TARGET_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FORBIDDEN_PREFIX_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:mpinv1_|mppi1_|mpcs1_|mpguest1_|mpdl1_|mprk1_)",
    re.IGNORECASE,
)


def validate_session_name(raw: str) -> str:
    cleaned = raw.strip()
    if not SAFE_SESSION_RE.fullmatch(cleaned):
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
    if FORBIDDEN_PREFIX_RE.search(cleaned):
        raise ValueError("refused chat target containing forbidden multiplayer secret token")
    if not SAFE_TARGET_RE.fullmatch(cleaned):
        raise ValueError("chat target must be a @handle, room code, or numeric party ID")
    return cleaned


def _resolve_binary_path(binary: str) -> str:
    """Resolve a bare command name to an absolute path so daemonized `phux` finds it."""
    if not binary or os.sep in binary or (os.altsep and os.altsep in binary):
        return binary
    found = shutil.which(binary)
    if found:
        return found
    home = Path.home()
    for candidate_dir in (
        home / ".local" / "bin",
        home / ".cargo" / "bin",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ):
        cand = candidate_dir / binary
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return binary


def _format_terminal_address(val: Any) -> str | None:
    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
        return f"@{val}"
    if isinstance(val, str):
        cleaned = val.strip()
        if not cleaned:
            return None
        if cleaned.isdigit():
            return f"@{cleaned}"
        return cleaned
    return None


def _extract_pane_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    if "terminal_id" in payload:
        addr = _format_terminal_address(payload.get("terminal_id"))
        if addr:
            return addr
    for key in ("terminal", "pane", "pane_id", "id"):
        val = payload.get(key)
        addr = _format_terminal_address(val)
        if addr:
            return addr
    for nested_key in ("pane", "terminal", "seed", "result"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            found = _extract_pane_id(nested)
            if found:
                return found
    return None


def _extract_session_active_terminal(ls_data: Any, session_name: str) -> str | None:
    if not isinstance(ls_data, dict):
        return None
    for host in ls_data.get("hosts", []):
        if not isinstance(host, dict):
            continue
        for sess in host.get("sessions", []):
            if isinstance(sess, dict) and sess.get("name") == session_name:
                addr = _format_terminal_address(sess.get("active_terminal"))
                if addr:
                    return addr
    return None


def launch_detached_chat(
    *,
    target: str | None = None,
    session: str = DEFAULT_SESSION_NAME,
    outpost_binary: str = "mp-outpost",
    phux_binary: str | None = None,
    tmux_binary: str | None = None,
    omarchy_tui_binary: str | None = None,
    runner: Any = None,
) -> dict[str, Any]:
    """Ensure a detached interactive `mp-outpost chat` window is running and return grab handles."""
    session_name = validate_session_name(session)
    clean_target = validate_chat_target(target)
    run_cmd = runner or subprocess.run

    resolved_outpost = _resolve_binary_path(outpost_binary)
    outpost_cmd = [resolved_outpost, "chat"]
    if clean_target is not None:
        outpost_cmd.append(clean_target)

    phux_bin = phux_binary if phux_binary is not None else _resolve_binary_path("phux")
    if phux_bin and (os.sep in phux_bin or shutil.which(phux_bin)):
        ls_proc = run_cmd(
            [phux_bin, "ls", "--json"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        existing_session: dict[str, Any] | None = None
        existing_terminal: str | None = None
        if ls_proc.returncode == 0 and ls_proc.stdout.strip():
            try:
                ls_data = json.loads(ls_proc.stdout)
                for sess in ls_data.get("sessions", []):
                    if isinstance(sess, dict) and sess.get("name") == session_name:
                        existing_session = sess
                        break
                existing_terminal = _extract_session_active_terminal(ls_data, session_name)
            except json.JSONDecodeError:
                existing_session = None

        if existing_session is not None:
            exec_info = existing_session.get("exec") or {}
            running_count = int(exec_info.get("running", 0) or 0) + int(exec_info.get("starting", 0) or 0)
            if running_count > 0:
                native_cmd = f"phux native attach {existing_terminal}" if existing_terminal else None
                return {
                    "ok": True,
                    "backend": "phux",
                    "session": session_name,
                    "pane_id": existing_terminal,
                    "reused": True,
                    "attach_cmd": f"phux attach {session_name}",
                    "native_cmd": native_cmd,
                    "message": (
                        f"Party chat is already running in detached phux session '{session_name}'"
                        + (f" ({existing_terminal})" if existing_terminal else "")
                        + f". Grab it with: phux attach {session_name}"
                        + (f"  (or standalone window: {native_cmd})" if native_cmd else "")
                    ),
                }
            # Stale empty/done session with same name: clean it up before recreating cleanly.
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
            native_cmd = f"phux native attach {pane_id}" if pane_id else None
            return {
                "ok": True,
                "backend": "phux",
                "session": session_name,
                "pane_id": pane_id,
                "reused": False,
                "attach_cmd": f"phux attach {session_name}",
                "native_cmd": native_cmd,
                "message": (
                    f"Started detached phux party chat in session '{session_name}'"
                    + (f" ({pane_id})" if pane_id else "")
                    + f". Grab it with: phux attach {session_name}"
                    + (f"  (or standalone window: {native_cmd})" if native_cmd else "")
                ),
            }
        # Clean up any failed/partial session created by `phux new` before falling back.
        if "spawn_failed" in (new_proc.stdout or "") or "spawn_failed" in (new_proc.stderr or ""):
            run_cmd(
                [phux_bin, "kill", "--yes", session_name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

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
            "Neither `phux`, `tmux`, nor `omarchy-launch-tui` was found on PATH. "
            f"Run directly in another terminal: {' '.join(outpost_cmd)}"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Launch mp-outpost chat in a detached phux window (with tmux/Omarchy fallback)."
    )
    parser.add_argument("target", nargs="?", default=None, help="Optional @handle, room code, or party ID.")
    parser.add_argument("--session", default=DEFAULT_SESSION_NAME, help="Detached session name (default: multiplayer-chat).")
    parser.add_argument("--binary", default="mp-outpost", help="Path to mp-outpost binary.")
    parser.add_argument("--json", action="store_true", help="Emit JSON result.")
    args = parser.parse_args(argv)
    try:
        res = launch_detached_chat(
            target=args.target,
            session=args.session,
            outpost_binary=args.binary,
        )
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(res["message"])
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
