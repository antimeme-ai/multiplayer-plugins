/**
 * OpenCode native plugin for multiplayer.tech (`mp-outpost` v0.7.0).
 *
 * IMPORTANT: OpenCode's plugin loader iterates all module exports and invokes each
 * export as a plugin initializer. This entry module therefore exports ONLY
 * `MultiplayerPlugin` (named + default); helper utilities live in `./security.ts`.
 */

import {
  MULTIPLAYER_MCP_CONFIG,
  MULTIPLAYER_SYSTEM_GUIDANCE,
  isMultiplayerToolName,
  scanValueForSecrets,
  type OpenCodeMcpLocalConfig,
} from "./security.ts";

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
  "tool.execute.before"?: (
    input: { tool: string; sessionID?: string; callID?: string },
    output: { args: unknown },
  ) => Promise<void> | void;
  "experimental.chat.system.transform"?: (
    input: { sessionID?: string; model?: unknown },
    output: { system: string[] },
  ) => Promise<void> | void;
}

export async function MultiplayerPlugin(
  ctx: OpenCodePluginContext,
): Promise<OpenCodeHooks> {
  let mcpNamespace = "multiplayer";

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
      if (!cfg.mcp[mcpNamespace]) {
        cfg.mcp[mcpNamespace] = { ...MULTIPLAYER_MCP_CONFIG };
        await log("info", "Registered local mp-outpost MCP server as 'multiplayer' (17 tools).");
      }
    },

    async event({ event }: { event?: { type?: string } }): Promise<void> {
      if (event?.type === "session.created") {
        await log(
          "debug",
          "Multiplayer Outpost ready; call outpost_status, party_invite, party_join, or party_post_card to collaborate in mp2 rooms.",
        );
      }
    },

    async "tool.execute.before"(
      input: { tool: string; sessionID?: string; callID?: string },
      output: { args: unknown },
    ): Promise<void> {
      if (!input?.tool || !isMultiplayerToolName(input.tool, mcpNamespace)) {
        return;
      }
      const secretKind = scanValueForSecrets(output?.args, { toolName: input.tool });
      if (secretKind !== null) {
        await log("warn", "Refused outbound multiplayer tool call containing forbidden secret material.", {
          tool: input.tool,
          secretKind,
        });
        throw new Error(
          `Refused ${input.tool}: detected forbidden multiplayer secret material (${secretKind}).`,
        );
      }
    },

    async "experimental.chat.system.transform"(
      _input: { sessionID?: string; model?: unknown },
      output: { system: string[] },
    ): Promise<void> {
      if (Array.isArray(output?.system) && !output.system.includes(MULTIPLAYER_SYSTEM_GUIDANCE)) {
        output.system.push(MULTIPLAYER_SYSTEM_GUIDANCE);
      }
    },
  };
}

export default MultiplayerPlugin;
