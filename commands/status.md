---
description: Check local mp-outpost identity, daemon health, CWT expiry, active party, and Safety Number alerts.
---

# `/status` — Multiplayer Outpost Status

1. Call `outpost_status` on the `multiplayer` MCP server (`mp-outpost mcp`).
2. Report:
   - Local handle, `account_id`, `device_id`, and device CWT expiry status.
   - Daemon health (`daemon_epoch`, PID, active party summary).
   - Security alerts: unpinned peers, `key_mismatch` flags, or dual-host churn notices.
3. If `mp-outpost` is unreachable or unconfigured, suggest calling `check_control_plane` / `set_me_up` on `https://multiplayer.tech/mcp` or running `mp-outpost doctor` locally.
4. Never display or request `root.key`, `device_secret`, `device_cwt`, `.mpkey`, or `mprk1_` recovery keys.
