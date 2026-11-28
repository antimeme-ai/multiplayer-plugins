---
description: Launch interactive mp-outpost party chat in a detached phux window (with tmux / Omarchy fallback) that you can grab in any terminal or native window.
---

# `/chat` — Open Detached Party Chat Window

Open live interactive **`mp-outpost chat`** in a detached **`phux`** session (`multiplayer-chat`) so the operator can grab it in a terminal or native window without interrupting this agent session:

1. Check if the operator provided an optional target (`@handle`, room code, or numeric `party_id`). Never pass secret tokens (`mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mprk1_`, `mpdl1_`) or `#fragment` invite URLs on command-line arguments.
2. Run the bundled detached launcher (`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/launch_party_chat.py" [target] --json`, or `python3 scripts/launch_party_chat.py [target] --json` outside Claude Code):
   - Resolves the absolute `mp-outpost` binary path (so daemonized `phux` finds `~/.local/bin/mp-outpost`), reuses an already-running `multiplayer-chat` session (returning its exact `@<id>` terminal address), cleans up stale/failed sessions, and falls back to `tmux` or `omarchy-launch-tui` when `phux` is not installed.
3. Reply concisely with the exact grab command(s) returned by the launcher:
   - Terminal attach: `phux attach multiplayer-chat`
   - Standalone native window (when `@<id>` is returned): `phux native attach @<id>`
   - (`tmux attach -t multiplayer-chat` when using the tmux fallback.)
