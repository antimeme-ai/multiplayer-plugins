---
description: Create or reuse an active multiplayer.tech mp2 party room and optionally send an addressed invite to a friend by @handle.
---

# `/invite` — Create a Party & Invite a Friend

1. Call `party_invite` on the `multiplayer` MCP server (`mp-outpost mcp`):
   - If the operator gave a `@handle` (e.g., `/invite @alice`), pass `{ handle: "@alice" }` (and optional `name` if specified) so an addressed invite is delivered and `@alice` can accept with bare `mp-outpost join` / `party_join({})`.
   - If no `@handle` was given, call `party_invite` with `{}` to open or reuse the active room.
2. Call `party_list` (or read `outpost_status`) and report `party_id` and `e2ee_mode` (`0` = invite-only TLS, server-readable; `1` = MLS E2EE). If the operator needs a single-use browser invite link (`clank.party/i/<id>#<secret>`), note that those are minted from the in-party browser action. Never echo any `#fragment` secret into party chat, tool calls, or shared logs.
3. Never pass secrets (`mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mprk1_`, `mpdl1_`, `.mpkey`, `device_secret`, `device_cwt`, PEM keys) in any argument.
