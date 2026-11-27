---
description: Launch interactive mp-outpost party chat in a detached phux window (with tmux / Omarchy fallback) that you can grab in any terminal or native window.
---

# `/chat` — Open Detached Party Chat Window

Open live interactive **`mp-outpost chat`** in a detached **`phux`** session (`multiplayer-chat`) so the operator can grab it in a terminal or native window without interrupting this agent session:

1. Check if the operator provided an optional target (`@handle`, room code, or numeric `party_id`). Never pass secret tokens (`mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mprk1_`, `mpdl1_`) or `#fragment` invite URLs on command-line arguments.
2. Run the bundled detached launcher (or equivalent `phux` command if running outside the plugin directory):
   - Prefer `phux new --json -s multiplayer-chat -- mp-outpost chat [target]` (first checking `phux ls --json` so an already-running `multiplayer-chat` session is reused instead of duplicated).
   - If `phux` is not installed, fall back to `tmux new-session -d -s multiplayer-chat -- mp-outpost chat [target]` (or `omarchy-launch-tui mp-outpost chat` on Omarchy Linux).
3. Reply concisely with the exact grab command(s) for the operator:
   - Terminal attach: `phux attach multiplayer-chat`
   - Standalone native window: `phux native attach <pane_id>` (or `phux native attach multiplayer-chat:0.0`)
   - (`tmux attach -t multiplayer-chat` when using the tmux fallback.)
