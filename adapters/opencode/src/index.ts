/**
 * OpenCode v2 server plugin (`@opencode/plugin` contract) for multiplayer.tech (`mp-outpost` v0.7.1).
 *
 * Exports a default OpenCode v2 plugin definition `{ id, setup(ctx) }` that:
 * - Registers the local `mp-outpost mcp` server via `ctx.mcp.transform(...)` without
 *   overwriting user customization.
 * - Enforces pre-exec secret refusal on all Multiplayer MCP tool calls via
 *   `ctx.tool.hook("tool.before", ...)`.
 * - Injects untrusted-peer provenance and secret-boundary guidance into session context
 *   when `ctx.session?.hook` is available.
 *
 * Zero `console.*` calls and zero external runtime dependencies. Helper utilities live
 * in `./security.ts`.
 */

import {
  MULTIPLAYER_MCP_CONFIG,
  MULTIPLAYER_SYSTEM_GUIDANCE,
  isMultiplayerToolName,
  scanValueForSecrets,
  type OpenCodeMcpLocalConfig,
} from "./security.ts";

export interface OpenCodeMcpRegistry {
  list?: () => Iterable<[string, OpenCodeMcpLocalConfig | Record<string, unknown>]>;
  get?: (id: string) => (OpenCodeMcpLocalConfig | Record<string, unknown>) | undefined;
  add?: (id: string, config: OpenCodeMcpLocalConfig) => void;
  set?: (id: string, config: OpenCodeMcpLocalConfig) => void;
}

export interface OpenCodeToolBeforeEvent {
  name?: string;
  tool?: string;
  input?: unknown;
  args?: unknown;
}

export interface OpenCodeSessionContextEvent {
  system?: Array<{ text?: string; [key: string]: unknown } | string>;
}

export interface OpenCodeV2ServerContext {
  mcp?: {
    transform?: (fn: (registry: OpenCodeMcpRegistry) => void) => Promise<void> | void;
  };
  tool?: {
    hook?: (
      event: "tool.before" | "tool.after",
      handler: (ev: OpenCodeToolBeforeEvent) => Promise<void> | void,
    ) => Promise<void> | void;
  };
  session?: {
    hook?: (
      event: string,
      handler: (ev: OpenCodeSessionContextEvent) => Promise<void> | void,
    ) => Promise<void> | void;
  };
}

const serverPlugin = {
  id: "antimeme-ai.multiplayer",
  async setup(ctx: OpenCodeV2ServerContext): Promise<void> {
    const mcpNamespace = "multiplayer";

    if (typeof ctx?.mcp?.transform === "function") {
      await ctx.mcp.transform((registry) => {
        const existing =
          typeof registry.get === "function"
            ? registry.get(mcpNamespace)
            : typeof registry.list === "function"
              ? [...registry.list()].find(([name]) => name === mcpNamespace)?.[1]
              : undefined;
        if (existing) return;
        const entry: OpenCodeMcpLocalConfig = { ...MULTIPLAYER_MCP_CONFIG };
        if (typeof registry.set === "function") {
          registry.set(mcpNamespace, entry);
        } else if (typeof registry.add === "function") {
          registry.add(mcpNamespace, entry);
        }
      });
    }

    if (typeof ctx?.tool?.hook === "function") {
      await ctx.tool.hook("tool.before", async (ev) => {
        const toolName = String(ev?.name ?? ev?.tool ?? "");
        if (!toolName || !isMultiplayerToolName(toolName, mcpNamespace)) {
          return;
        }
        const payload = ev?.input !== undefined ? ev.input : ev?.args;
        const secretKind = scanValueForSecrets(payload, { toolName });
        if (secretKind !== null) {
          throw new Error(
            `Refused ${toolName}: detected forbidden multiplayer secret material (${secretKind}).`,
          );
        }
      });
    }

    if (typeof ctx?.session?.hook === "function") {
      await ctx.session.hook("context", (ev) => {
        if (!Array.isArray(ev?.system)) return;
        const already = ev.system.some((item) =>
          typeof item === "string"
            ? item === MULTIPLAYER_SYSTEM_GUIDANCE
            : item?.text === MULTIPLAYER_SYSTEM_GUIDANCE,
        );
        if (!already) {
          ev.system.push({ text: MULTIPLAYER_SYSTEM_GUIDANCE });
        }
      });
    }
  },
};

export default serverPlugin;
