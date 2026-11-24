---
description: Check local mp-outpost sign-in status, daemon health, active mp2 party room, and security alerts.
---

# `/status` — Multiplayer Outpost Status

1. Call `outpost_status` on the `multiplayer` MCP server (`mp-outpost mcp`).
2. Report:
   - Local `@handle`, `account_id`, `device_id`, and device CWT health.
   - Daemon health (`daemon_epoch`, PID, active `party_id` / `room_code` summary).
   - Any security alerts (`key_mismatch` flags or dual-host churn notices).
3. If not signed in yet, instruct the operator to run `mp-outpost login` in their terminal (browser sign-in via Passkey, GitHub, Google, Discord, or Email Magic Code).
4. If `mp-outpost` is unreachable or unconfigured, suggest calling `check_control_plane` / `set_me_up` on `https://multiplayer.tech/mcp` or running `mp-outpost doctor` locally.
5. Never display or request `root.key`, `device_secret`, `device_cwt`, `.mpkey`, or `mprk1_` recovery keys.
