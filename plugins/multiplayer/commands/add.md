---
description: Send or accept a multiplayer.tech friend request by @handle via mp-outpost.
---

# `/add` — Add or Accept a Friend

1. Validate that the operator provided a `@handle` (never a secret token or key).
2. Call `friend_add` (`{ handle }`) on the `multiplayer` MCP server (`mp-outpost mcp`).
3. Report whether the friend request was sent or mutually accepted (`@handle` is now a friend) and remind the operator they can now ring them with `/invite @handle`.
