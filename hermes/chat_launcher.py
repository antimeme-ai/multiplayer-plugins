"""Detached `phux` and in-place `mp-outpost chat` launcher for Hermes Agent.

Zero external dependencies (Python 3 stdlib only). Refuses secret tokens and
`#fragment` invite URLs before spawning any subprocess (`shell=False`).
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import subprocess
import threading
import weakref
from pathlib import Path
from typing import Any, Callable

from .security import (
    SecretRefusalError,
    redact_url_fragments,
    refuse_secrets,
    sanitize_peer_text,
    sanitize_single_line,
)

DEFAULT_SESSION_NAME = "multiplayer-chat"
MAX_SAFE_PARTY_ID = (1 << 53) - 1
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


def _resolve_binary_path(binary: str) -> str:
    """Resolve bare command names to absolute paths so daemonized `phux` finds them."""
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
        addr = _format_terminal_address(payload.get(key))
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

    outpost_cmd = [_resolve_binary_path(outpost_binary)]
    if state_dir:
        outpost_cmd.extend(["--state-dir", state_dir])
    outpost_cmd.append("chat")
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
                        + (f" (or window: {native_cmd})" if native_cmd else "")
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
                    + (f" (or window: {native_cmd})" if native_cmd else "")
                ),
            }
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


def _default_inline_emit(line: str) -> None:
    """Print a sanitized inline party line cleanly above the Hermes prompt."""
    try:
        from prompt_toolkit.application import get_app_or_none, run_in_terminal

        if get_app_or_none() is not None:
            run_in_terminal(lambda: print(line, flush=True))
            return
    except Exception:
        pass
    print(line, flush=True)


def _extract_event_body(raw_event: dict[str, Any]) -> str:
    for key in ("text", "body", "message"):
        val = raw_event.get(key)
        if isinstance(val, str) and val.strip():
            return val
    payload = raw_event.get("payload")
    if isinstance(payload, str) and payload.strip():
        return payload
    if isinstance(payload, dict):
        if payload.get("type") == "agent_card" or "title" in payload:
            title = str(payload.get("title", "")).strip()
            summary = str(payload.get("summary", "")).strip()
            status = str(payload.get("status", "")).strip()
            tag = f"[{status}] " if status else ""
            if title and summary:
                return f"card: {tag}{title} — {summary}"
            if title or summary:
                return f"card: {tag}{title or summary}"
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return ""


class InlinePartyWatcher:
    """Zero-token background inline party feed for interactive Hermes sessions.

    Streams sanitized incoming messages directly above the Hermes prompt via
    bounded `mp-outpost --json party wait` loops without triggering LLM turns.
    """

    def __init__(
        self,
        *,
        outpost_binary: str = "mp-outpost",
        state_dir: str | None = None,
        wait_timeout_ms: int = 25_000,
        emit_fn: Callable[[str], None] | None = None,
        popen_factory: Any = None,
        run_factory: Any = None,
        idle_backoff_s: float = 2.0,
    ) -> None:
        self.outpost_binary = outpost_binary
        self.state_dir = state_dir
        self.wait_timeout_ms = max(1_000, min(int(wait_timeout_ms), 45_000))
        self._emit_fn = emit_fn or _default_inline_emit
        self._popen = popen_factory or subprocess.Popen
        self._run = run_factory or subprocess.run
        self._idle_backoff_s = max(0.05, float(idle_backoff_s))

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: Any = None
        self._atexit_registered = False

        self.party_id: int | None = None
        self._pinned_party: bool = False
        self.after_seq: int = 0
        self.daemon_epoch: int = 0
        self.self_device_id: int = 0
        self.received_count: int = 0
        self.last_error: str | None = None

    def _base_argv(self) -> list[str]:
        argv = [_resolve_binary_path(self.outpost_binary)]
        if self.state_dir:
            argv.extend(["--state-dir", self.state_dir])
        argv.append("--json")
        return argv

    def _run_json(self, sub_args: list[str], timeout_s: float = 5.0) -> tuple[dict[str, Any] | None, str]:
        try:
            proc = self._run(
                self._base_argv() + sub_args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, redact_url_fragments(str(exc))
        if proc.returncode != 0 or not (proc.stdout or "").strip():
            return None, redact_url_fragments((proc.stderr or proc.stdout or "").strip())
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None, "invalid json from mp-outpost"
        return (parsed if isinstance(parsed, dict) else None), ""

    def _discover_party(self, preferred_party_id: int | None = None) -> tuple[int | None, int, int, str]:
        listed, err = self._run_json(["party", "list"], timeout_s=5.0)
        if not listed:
            return None, 0, 0, err or "failed to query mp-outpost party list"
        parties = listed.get("parties") or []
        if not parties:
            return None, 0, 0, "No active multiplayer party found. Join or open one first with /party-join or /party-invite."
        chosen = None
        if preferred_party_id is not None:
            chosen = next(
                (p for p in parties if isinstance(p, dict) and int(p.get("party_id", 0) or 0) == preferred_party_id),
                None,
            )
            if chosen is None:
                return None, 0, 0, f"Party #{preferred_party_id} is not active."
        if chosen is None:
            chosen = parties[0]
        pid = int(chosen["party_id"])
        raw_next = chosen.get("next_seq")
        seed_seq = int(raw_next) if isinstance(raw_next, int) and raw_next > 0 else 0
        epoch = int(listed.get("daemon_epoch", chosen.get("daemon_epoch", 0)) or 0)
        return pid, seed_seq, epoch, ""

    def _refresh_self_device(self) -> None:
        st, _ = self._run_json(["party", "status"], timeout_s=3.0)
        if st:
            dev_id = st.get("device_id")
            if isinstance(dev_id, int) and dev_id > 0:
                self.self_device_id = dev_id

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def _terminate_active_proc(self) -> None:
        with self._lock:
            proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    proc.kill()
        except Exception:
            pass

    def start(self, target: str | None = None) -> dict[str, Any]:
        """Start streaming live incoming party messages inline above the prompt."""
        requested_pid: int | None = None
        if target is not None and target.strip():
            cleaned = target.strip()
            if cleaned.startswith("-") or "#" in cleaned:
                raise ValueError("inline party target must be a positive numeric party_id")
            refuse_secrets(cleaned)
            try:
                requested_pid = int(cleaned)
            except ValueError as exc:
                raise ValueError("Usage: /party-chat --inline [on|off|status|<party_id>]") from exc
            if requested_pid < 1 or requested_pid > MAX_SAFE_PARTY_ID:
                raise ValueError(f"party_id must be in 1..={MAX_SAFE_PARTY_ID}")

        with self._lock:
            running = self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()
            if running and (requested_pid is None or requested_pid == self.party_id):
                return {
                    "ok": True,
                    "running": True,
                    "already_running": True,
                    "party_id": self.party_id,
                    "after_seq": self.after_seq,
                    "message": (
                        f"Inline party feed already running for party #{self.party_id} "
                        f"(seq={self.after_seq}). Reply with /party-say <msg> or stop with /party-chat --inline off."
                    ),
                }

        if self.is_running:
            self.stop()

        pid, seed_seq, epoch, err = self._discover_party(requested_pid)
        if pid is None:
            return {"ok": False, "running": False, "party_id": None, "message": err}

        self._refresh_self_device()
        with self._lock:
            self.party_id = pid
            self._pinned_party = requested_pid is not None
            self.after_seq = seed_seq
            self.daemon_epoch = epoch
            self.last_error = None
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._watch_loop,
                name="hermes-multiplayer-inline",
                daemon=True,
            )
            self._thread = thread
            if not self._atexit_registered:
                weak_self = weakref.ref(self)

                def _cleanup() -> None:
                    inst = weak_self()
                    if inst is not None:
                        inst.stop()

                atexit.register(_cleanup)
                self._atexit_registered = True
            thread.start()

        return {
            "ok": True,
            "running": True,
            "already_running": False,
            "party_id": pid,
            "after_seq": seed_seq,
            "message": (
                f"Inline party feed started for party #{pid} (live from seq={seed_seq}, zero LLM tokens). "
                "Reply with /party-say <message>; stop with /party-chat --inline off."
            ),
        }

    def stop(self) -> dict[str, Any]:
        """Stop the inline party feed and terminate any in-flight party wait child."""
        with self._lock:
            was_running = self._thread is not None and self._thread.is_alive()
            self._stop_event.set()
            thread = self._thread
        self._terminate_active_proc()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            self._thread = None
            self._proc = None
        return {
            "ok": True,
            "running": False,
            "was_running": was_running,
            "message": (
                "Stopped inline party feed."
                if was_running
                else "Inline party feed is not running."
            ),
        }

    def status(self) -> dict[str, Any]:
        running = self.is_running
        if running:
            msg = (
                f"Inline party feed: ON (party #{self.party_id}, seq={self.after_seq}, "
                f"received={self.received_count}). Reply with /party-say <message> or stop with /party-chat --inline off."
            )
        else:
            msg = "Inline party feed: OFF. Start with /party-chat --inline."
        return {
            "running": running,
            "party_id": self.party_id,
            "after_seq": self.after_seq,
            "received_count": self.received_count,
            "last_error": self.last_error,
            "message": msg,
        }

    def _watch_loop(self) -> None:
        while not self._stop_event.is_set():
            pid = self.party_id
            if pid is None:
                discovered_pid, seed_seq, epoch, err = self._discover_party(None)
                if discovered_pid is None:
                    self.last_error = err
                    self._stop_event.wait(self._idle_backoff_s)
                    continue
                self.party_id = discovered_pid
                self.after_seq = seed_seq
                self.daemon_epoch = epoch
                pid = discovered_pid

            argv = self._base_argv() + [
                "party",
                "wait",
                str(pid),
                "--after-seq",
                str(self.after_seq),
                "--timeout-ms",
                str(self.wait_timeout_ms),
            ]
            if self.daemon_epoch > 0:
                argv.extend(["--cursor-epoch", str(self.daemon_epoch)])

            proc: Any = None
            try:
                proc = self._popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                with self._lock:
                    self._proc = proc
                stdout, stderr = proc.communicate(timeout=(self.wait_timeout_ms / 1000.0) + 10.0)
                rc = int(proc.returncode if proc.returncode is not None else 1)
            except subprocess.TimeoutExpired:
                self._terminate_active_proc()
                continue
            except OSError as exc:
                self.last_error = redact_url_fragments(str(exc))
                self._stop_event.wait(self._idle_backoff_s)
                continue
            finally:
                with self._lock:
                    if self._proc is proc:
                        self._proc = None

            if self._stop_event.is_set():
                break

            if rc != 0:
                err_text = redact_url_fragments((stderr or stdout or "").strip())
                err_lower = err_text.lower()
                if "is not active" in err_lower or "code=4040" in err_lower:
                    if not self._pinned_party:
                        self.party_id = None
                    self.after_seq = 0
                    self.daemon_epoch = 0
                self.last_error = err_text or f"mp-outpost exited with status {rc}"
                self._stop_event.wait(self._idle_backoff_s)
                continue

            if not (stdout or "").strip():
                continue

            try:
                resp = json.loads(stdout)
            except json.JSONDecodeError:
                self.last_error = "invalid json from mp-outpost party wait"
                self._stop_event.wait(self._idle_backoff_s)
                continue

            if not isinstance(resp, dict):
                continue

            self.last_error = None
            new_epoch = int(resp.get("daemon_epoch", self.daemon_epoch) or 0)
            if new_epoch > 0:
                self.daemon_epoch = new_epoch

            cursor_reset = bool(resp.get("cursor_reset", False))
            events_raw = resp.get("events") or []
            max_seq = self.after_seq
            for ev in events_raw:
                if not isinstance(ev, dict):
                    continue
                ev_seq = int(ev.get("event_seq", ev.get("seq", 0)) or 0)
                if ev_seq > max_seq:
                    max_seq = ev_seq
                kind = str(ev.get("kind", "unknown"))
                if kind in ("membership_changed", "system"):
                    continue
                sender_client = sanitize_single_line(str(ev.get("sender_client", ev.get("client", ""))))
                is_browser = bool(ev.get("is_browser", False)) or sender_client.lower() in ("web", "browser")
                sender_device_id = int(ev.get("sender_device_id", 0) or 0)
                if (
                    not is_browser
                    and self.self_device_id > 0
                    and sender_device_id > 0
                    and sender_device_id == self.self_device_id
                ):
                    continue
                raw_body = _extract_event_body(ev)
                clean_body = redact_url_fragments(sanitize_peer_text(raw_body)).strip()
                if not clean_body:
                    continue
                handle = sanitize_single_line(str(ev.get("sender_handle", ev.get("from", "peer")))) or "peer"
                if not handle.startswith("@"):
                    handle = f"@{handle}"
                origin_tag = " [browser]" if is_browser else ""
                line = f"[party #{pid} {handle}{origin_tag}] {clean_body}"
                self.received_count += 1
                try:
                    self._emit_fn(line)
                except Exception:
                    pass

            if "next_seq" in resp and resp["next_seq"] is not None:
                next_seq = int(resp["next_seq"])
                self.after_seq = next_seq if cursor_reset else max(max_seq, next_seq)
            else:
                self.after_seq = max_seq


__all__ = [
    "DEFAULT_SESSION_NAME",
    "InlinePartyWatcher",
    "SecretRefusalError",
    "launch_detached_chat",
    "run_chat_in_place",
    "validate_chat_target",
    "validate_session_name",
]
