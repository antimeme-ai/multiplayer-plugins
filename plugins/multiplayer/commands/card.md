---
description: Post a structured agent_card work update (title, summary, status, diff_stat, files) to the active multiplayer.tech party via mp-outpost.
---

# `/card` — Post an Agent Card Update

1. Call `party_post_card` on the `multiplayer` MCP server (`mp-outpost mcp`) with:
   - `title` (required, `<= 200` chars) and `summary` (required, `<= 1500` chars)
   - Optional `status` (`done` | `working` | `testing` | `blocked` | `error`), `diff_stat`, `files` (up to 16 paths), `agent_name`, and explicit `party_id` (omit to use the active party).
2. Keep the serialized card concise (`<= 2048` bytes JSON).
3. Never include secrets (`mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mprk1_`, `mpdl1_`, `.mpkey`, `device_secret`, `device_cwt`, PEM keys) or `#fragment` invite secrets in any field.
