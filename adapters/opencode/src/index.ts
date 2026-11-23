/**
 * OpenCode native plugin for multiplayer.tech (`mp-outpost mcp`).
 *
 * - Injects the local `multiplayer` stdio MCP server (`["mp-outpost", "mcp"]`)
 *   into OpenCode's runtime configuration without overwriting user customizations.
 * - Logs strictly via `ctx.client.app.log(...)` (never `console.log`, which corrupts OpenCode's TUI).
 * - Never touches local mp-outpost keys (`root.key`, `.mpkey`, `device_secret`).
 */

export interface OpenCodeMcpLocalConfig {
  type: "local";
  command: string[];
  enabled: boolean;
}

export interface OpenCodeConfig {
  mcp?: Record<string, OpenCodeMcpLocalConfig | Record<string, unknown>>;
  [key: string]: unknown;
}

export interface OpenCodeLogEntry {
  service: string;
  level: "debug" | "info" | "warn" | "error";
  message: string;
  extra?: Record<string, unknown>;
}

export interface OpenCodePluginContext {
  client?: {
    app?: {
      log?: (entry: { body: OpenCodeLogEntry }) => Promise<void> | void;
    };
  };
}

export interface OpenCodeHooks {
  config?: (cfg: OpenCodeConfig) => Promise<void> | void;
  event?: (payload: { event?: { type?: string } }) => Promise<void> | void;
}

export const MULTIPLAYER_MCP_CONFIG: OpenCodeMcpLocalConfig = {
  type: "local",
  command: ["mp-outpost", "mcp"],
  enabled: true,
};

export async function MultiplayerPlugin(
  ctx: OpenCodePluginContext,
): Promise<OpenCodeHooks> {
  const log = async (
    level: OpenCodeLogEntry["level"],
    message: string,
    extra?: Record<string, unknown>,
  ): Promise<void> => {
    try {
      await ctx.client?.app?.log?.({
        body: {
          service: "multiplayer-outpost",
          level,
          message,
          ...(extra ? { extra } : {}),
        },
      });
    } catch {
      // Never write to stdout/stderr inside OpenCode's TUI process.
    }
  };

  return {
    async config(cfg: OpenCodeConfig): Promise<void> {
      if (!cfg.mcp) {
        cfg.mcp = {};
      }
      if (!cfg.mcp.multiplayer) {
        cfg.mcp.multiplayer = { ...MULTIPLAYER_MCP_CONFIG };
        await log("info", "Registered local mp-outpost MCP server as 'multiplayer'.");
      }
    },

    async event({ event }: { event?: { type?: string } }): Promise<void> {
      if (event?.type === "session.created") {
        await log(
          "debug",
          "Multiplayer Outpost ready; call outpost_status and party_list to inspect active E2EE P2P parties.",
        );
      }
    },
  };
}

export default MultiplayerPlugin;
