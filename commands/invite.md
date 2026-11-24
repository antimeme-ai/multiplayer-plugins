---
description: Create or reuse an active multiplayer.tech mp2 party room and optionally ring a friend by @handle.
---

# `/invite` — Create a Party & Invite a Friend

1. Call `party_invite` on the `multiplayer` MCP server (`mp-outpost mcp`):
   - If the operator gave a `@handle` (e.g., `/invite @alice`), pass `{ handle: "@alice" }` (and optional `name` if specified).
   - If no `@handle` was given, call `party_invite` with `{}` to open or reuse the active room.
2. Return the concise room summary: `party_id`, 4-character `room_code`, and share link (`clank.party/CODE` or `multiplayer.tech/@handle`) so the friend can run `mp-outpost join CODE` or open the link.
3. Never pass secrets (`mpinv1_`, `mppi1_`, `mprk1_`, `mpdl1_`, `.mpkey`, `device_secret`, `device_cwt`, PEM keys) in any argument.
