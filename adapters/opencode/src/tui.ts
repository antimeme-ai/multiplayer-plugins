/**
 * OpenCode TUI plugin (`@opencode/plugin/tui` contract) for multiplayer.tech.
 *
 * Adds a one-key shortcut (`ctrl+shift+p`), Command Palette entry ("Open Multiplayer
 * Party Chat"), and `/party-chat` (`/mp-chat`) slash completion that launches
 * `mp-outpost chat` in a detached `phux` window (with `tmux` / `omarchy-launch-tui`
 * fallback) and shows an OpenCode toast with the exact grab commands.
 *
 * Zero `console.*` calls and zero external runtime dependencies.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectForbiddenSecret } from "./security.ts";

const DEFAULT_SESSION = "multiplayer-chat";
const SAFE_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_TARGET_RE = /^@?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface OpenCodeTuiToast {
  show(options: { title?: string; message: string; variant?: "info" | "success" | "warning" | "error"; duration?: number }): void;
}

export interface OpenCodeTuiKeymapCommand {
  readonly id?: string;
  readonly title?: string;
  readonly description?: string;
  readonly group?: string;
  readonly bind?: false | string;
  readonly palette?: true;
  readonly slash?: { readonly name: string; readonly aliases?: string[]; readonly arguments?: true };
  readonly suggested?: boolean | (() => boolean);
  readonly run: (input?: string) => void | false | Promise<void>;
}

export interface OpenCodeTuiContext {
  readonly keymap: {
    layer(factory: () => { readonly mode?: string; readonly commands?: readonly OpenCodeTuiKeymapCommand[] }): void;
  };
  readonly ui: {
    readonly toast: OpenCodeTuiToast;
    readonly slot?: (spec: { readonly append?: string; readonly prepend?: string; readonly render: () => unknown }) => void;
  };
}

export interface DetachedChatLaunchResult {
  ok: boolean;
  backend: "phux" | "tmux" | "omarchy-launch-tui" | "manual";
  session: string;
  paneId?: string;
  reused: boolean;
  attachCmd: string;
  nativeCmd?: string;
  message: string;
}

async function execCapture(
  binary: string,
  args: string[],
  timeoutMs = 10_000,
): Promise<{ code: number; stdout: string; stderr: string; notFound?: boolean }> {
  return await new Promise((resolve) => {
    let settled = false;
    const child = spawn(binary, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGTERM");
      } catch {
        // ignore
      }
      resolve({ code: 124, stdout: "", stderr: "timed out" });
    }, timeoutMs);
    child.stdout.on("data", (c: Buffer) => outChunks.push(c));
    child.stderr.on("data", (c: Buffer) => errChunks.push(c));
    child.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: err.code === "ENOENT" ? 127 : 1, stdout: "", stderr: err.message, notFound: err.code === "ENOENT" });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(outChunks).toString("utf8").trim(),
        stderr: Buffer.concat(errChunks).toString("utf8").trim(),
      });
    });
  });
}

function resolveBinaryPath(binary: string): string {
  if (!binary || binary.includes("/") || binary.includes("\\")) return binary;
  const searchDirs = [
    ...(process.env.PATH ? process.env.PATH.split(path.delimiter) : []),
    path.join(os.homedir(), ".local", "bin"),
    path.join(os.homedir(), ".cargo", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
  ];
  for (const dir of searchDirs) {
    if (!dir) continue;
    const cand = path.join(dir, binary);
    try {
      fs.accessSync(cand, fs.constants.X_OK);
      if (fs.statSync(cand).isFile()) return cand;
    } catch {
      // continue
    }
  }
  return binary;
}

function formatTerminalAddress(val: unknown): string | undefined {
  if (typeof val === "number" && Number.isInteger(val) && val > 0) return `@${val}`;
  if (typeof val === "string") {
    const cleaned = val.trim();
    if (!cleaned) return undefined;
    if (/^\d+$/.test(cleaned)) return `@${cleaned}`;
    return cleaned;
  }
  return undefined;
}

function extractPaneId(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const obj = payload as Record<string, unknown>;
  if ("terminal_id" in obj) {
    const addr = formatTerminalAddress(obj.terminal_id);
    if (addr) return addr;
  }
  for (const k of ["terminal", "pane", "pane_id", "id"]) {
    const addr = formatTerminalAddress(obj[k]);
    if (addr) return addr;
  }
  for (const k of ["pane", "terminal", "seed", "result"]) {
    const nested = extractPaneId(obj[k]);
    if (nested) return nested;
  }
  return undefined;
}

function extractActiveTerminal(lsData: unknown, session: string): string | undefined {
  if (!lsData || typeof lsData !== "object" || Array.isArray(lsData)) return undefined;
  const hosts = (lsData as { hosts?: unknown[] }).hosts;
  if (!Array.isArray(hosts)) return undefined;
  for (const host of hosts) {
    if (!host || typeof host !== "object") continue;
    const sessions = (host as { sessions?: unknown[] }).sessions;
    if (!Array.isArray(sessions)) continue;
    for (const s of sessions) {
      if (s && typeof s === "object" && (s as { name?: unknown }).name === session) {
        const addr = formatTerminalAddress((s as { active_terminal?: unknown }).active_terminal);
        if (addr) return addr;
      }
    }
  }
  return undefined;
}

export async function launchDetachedPartyChat(options?: {
  target?: string;
  session?: string;
  outpostBinary?: string;
  phuxBinary?: string;
  tmuxBinary?: string;
  omarchyTuiBinary?: string;
}): Promise<DetachedChatLaunchResult> {
  const session = (options?.session ?? DEFAULT_SESSION).trim();
  if (!SAFE_SESSION_RE.test(session)) {
    throw new Error(`Invalid session name '${session}'.`);
  }
  let cleanTarget: string | undefined;
  if (options?.target?.trim()) {
    const raw = options.target.trim();
    if (raw.startsWith("-")) throw new Error("Refused chat target: value cannot start with '-'.");
    if (raw.includes("#")) {
      throw new Error("Refused #fragment invite URL on argv: redeem fragment links directly via `mp-outpost join`.");
    }
    const secret = detectForbiddenSecret(raw);
    if (secret !== null) throw new Error(`Refused chat target: detected forbidden secret material (${secret}).`);
    if (!SAFE_TARGET_RE.test(raw)) throw new Error("Chat target must be a @handle, room code, or numeric party ID.");
    cleanTarget = raw;
  }

  const resolvedOutpost = resolveBinaryPath(options?.outpostBinary?.trim() || "mp-outpost");
  const outpostCmd = [resolvedOutpost, "chat", ...(cleanTarget ? [cleanTarget] : [])];
  const phuxBin = resolveBinaryPath(options?.phuxBinary ?? process.env.PHUX_BIN?.trim() ?? "phux");
  const lsRes = await execCapture(phuxBin, ["ls", "--json"]);
  if (!lsRes.notFound) {
    let existingFound = false;
    let existingRunning = false;
    let existingTerminal: string | undefined;
    if (lsRes.code === 0 && lsRes.stdout) {
      try {
        const parsed = JSON.parse(lsRes.stdout) as {
          sessions?: Array<{ name?: string; exec?: { running?: number; starting?: number } }>;
        };
        const found = parsed.sessions?.find((s) => s?.name === session);
        if (found) {
          existingFound = true;
          existingRunning = Number(found.exec?.running ?? 0) + Number(found.exec?.starting ?? 0) > 0;
          if (existingRunning) existingTerminal = extractActiveTerminal(parsed, session);
        }
      } catch {
        // ignore
      }
    }
    if (existingRunning) {
      const nativeCmd = existingTerminal ? `phux native attach ${existingTerminal}` : undefined;
      return {
        ok: true,
        backend: "phux",
        session,
        ...(existingTerminal ? { paneId: existingTerminal } : {}),
        reused: true,
        attachCmd: `phux attach ${session}`,
        ...(nativeCmd ? { nativeCmd } : {}),
        message: `Party chat running in detached phux '${session}'${existingTerminal ? ` (${existingTerminal})` : ""}. Grab: phux attach ${session}${nativeCmd ? ` | window: ${nativeCmd}` : ""}`,
      };
    }
    if (existingFound) await execCapture(phuxBin, ["kill", "--yes", session]);
    const created = await execCapture(phuxBin, ["new", "--json", "-s", session, "--", ...outpostCmd], 15_000);
    if (created.code === 0) {
      let paneId: string | undefined;
      if (created.stdout) {
        try {
          paneId = extractPaneId(JSON.parse(created.stdout));
        } catch {
          // ignore
        }
      }
      const nativeCmd = paneId ? `phux native attach ${paneId}` : undefined;
      return {
        ok: true,
        backend: "phux",
        session,
        ...(paneId ? { paneId } : {}),
        reused: false,
        attachCmd: `phux attach ${session}`,
        ...(nativeCmd ? { nativeCmd } : {}),
        message: `Started detached phux chat '${session}'${paneId ? ` (${paneId})` : ""}. Grab: phux attach ${session}${nativeCmd ? ` | window: ${nativeCmd}` : ""}`,
      };
    }
    if (created.stdout.includes("spawn_failed") || created.stderr.includes("spawn_failed")) {
      await execCapture(phuxBin, ["kill", "--yes", session]);
    }
  }

  const tmuxBin = options?.tmuxBinary ?? "tmux";
  const hasTmux = await execCapture(tmuxBin, ["has-session", "-t", session], 5_000);
  if (!hasTmux.notFound) {
    if (hasTmux.code === 0) {
      return {
        ok: true,
        backend: "tmux",
        session,
        reused: true,
        attachCmd: `tmux attach -t ${session}`,
        message: `Party chat running in detached tmux '${session}'. Grab: tmux attach -t ${session}`,
      };
    }
    const created = await execCapture(tmuxBin, ["new-session", "-d", "-s", session, "--", ...outpostCmd]);
    if (created.code === 0) {
      return {
        ok: true,
        backend: "tmux",
        session,
        reused: false,
        attachCmd: `tmux attach -t ${session}`,
        message: `Started detached tmux chat '${session}'. Grab: tmux attach -t ${session}`,
      };
    }
  }

  const omarchyBin = options?.omarchyTuiBinary ?? "omarchy-launch-tui";
  const hasOmarchy = await execCapture("which", [omarchyBin], 3_000);
  if (hasOmarchy.code === 0) {
    const child = spawn(omarchyBin, outpostCmd, { shell: false, detached: true, stdio: "ignore" });
    child.unref();
    return {
      ok: true,
      backend: "omarchy-launch-tui",
      session,
      reused: false,
      attachCmd: outpostCmd.join(" "),
      message: "Launched mp-outpost chat in a native Omarchy TUI window.",
    };
  }

  return {
    ok: false,
    backend: "manual",
    session,
    reused: false,
    attachCmd: outpostCmd.join(" "),
    message: `Run in another terminal: ${outpostCmd.join(" ")}`,
  };
}

const tuiPlugin = {
  id: "antimeme-ai.multiplayer",
  setup(context: OpenCodeTuiContext): void {
    const registerLayer = () => {
      context.keymap.layer(() => ({
        mode: "global",
        commands: [
          {
            id: "multiplayer.chat",
            title: "Open Multiplayer Party Chat",
            description: "Launch mp-outpost chat in a detached phux window (tmux/Omarchy fallback)",
            group: "Multiplayer",
            bind: "ctrl+alt+m",
            palette: true,
            slash: { name: "party-chat", aliases: ["mp-chat"], arguments: true },
            suggested: true,
            async run(input?: string) {
              try {
                const res = await launchDetachedPartyChat({ target: input?.trim() || undefined });
                context.ui.toast.show({
                  title: "Multiplayer Party Chat",
                  message: res.message,
                  variant: res.ok ? "success" : "warning",
                  duration: 6000,
                });
              } catch (err) {
                context.ui.toast.show({
                  title: "Multiplayer Party Chat",
                  message: (err as Error).message,
                  variant: "error",
                  duration: 6000,
                });
              }
            },
          },
        ],
      }));
      return null;
    };

    if (typeof context.ui?.slot === "function") {
      context.ui.slot({
        append: "app",
        render: registerLayer,
      });
    } else {
      registerLayer();
    }
  },
};

export default tuiPlugin;
