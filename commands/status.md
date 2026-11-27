---
description: Check mp-outpost authentication, MLS E2EE status, daemon health, active party summary, and security alerts.
---

# `/status` — Multiplayer Outpost Status

1. Call `outpost_status` on the `multiplayer` MCP server (`mp-outpost mcp`).
2. Report:
   - Authentication state (`authenticated`, `ready`), local `@handle`, `account_id`, `device_id`, and device CWT health.
   - Daemon health (`daemon_epoch`, PID, active `party_id` / `room_code`, MLS `e2ee_mode`, `mls_epoch`, `trust_tier` 0–3, `has_declared_agent`).
   - Any security alerts (`key_mismatch_alerts`, `clone_detected`, or `dual_host_churn_alert`).
3. If `authenticated: false`, explain that browser login on `multiplayer.tech` is separate from CLI device authorization and instruct the operator to run `mp-outpost login` in their terminal.
4. If `mp-outpost` is unreachable or unconfigured, suggest calling `check_control_plane` / `set_me_up` on `https://multiplayer.tech/mcp` or running `mp-outpost doctor --trace` locally.
5. Never display or request `root.key`, `device_secret`, `device_cwt`, `.mpkey`, or `mprk1_` recovery keys.
