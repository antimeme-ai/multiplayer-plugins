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
    layer(factory: () => { readonly commands?: readonly OpenCodeTuiKeymapCommand[] }): void;
  };
  readonly ui: {
    readonly toast: OpenCodeTuiToast;
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

function extractPaneId(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const obj = payload as Record<string, unknown>;
  for (const k of ["terminal", "pane", "pane_id", "id"]) {
    if (typeof obj[k] === "string" && (obj[k] as string).trim()) return (obj[k] as string).trim();
  }
  for (const k of ["pane", "terminal", "seed", "result"]) {
    const nested = extractPaneId(obj[k]);
    if (nested) return nested;
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

  const outpostCmd = [options?.outpostBinary?.trim() || "mp-outpost", "chat", ...(cleanTarget ? [cleanTarget] : [])];
  const phuxBin = options?.phuxBinary ?? process.env.PHUX_BIN?.trim() ?? "phux";
  const lsRes = await execCapture(phuxBin, ["ls", "--json"]);
  if (!lsRes.notFound) {
    let existingFound = false;
    let existingRunning = false;
    if (lsRes.code === 0 && lsRes.stdout) {
      try {
        const parsed = JSON.parse(lsRes.stdout) as {
          sessions?: Array<{ name?: string; exec?: { running?: number; starting?: number } }>;
        };
        const found = parsed.sessions?.find((s) => s?.name === session);
        if (found) {
          existingFound = true;
          existingRunning = Number(found.exec?.running ?? 0) + Number(found.exec?.starting ?? 0) > 0;
        }
      } catch {
        // ignore
      }
    }
    if (existingRunning) {
      return {
        ok: true,
        backend: "phux",
        session,
        reused: true,
        attachCmd: `phux attach ${session}`,
        nativeCmd: `phux native attach ${session}:0.0`,
        message: `Party chat running in detached phux '${session}'. Grab: phux attach ${session}`,
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
      const nativeTarget = paneId ?? `${session}:0.0`;
      return {
        ok: true,
        backend: "phux",
        session,
        ...(paneId ? { paneId } : {}),
        reused: false,
        attachCmd: `phux attach ${session}`,
        nativeCmd: `phux native attach ${nativeTarget}`,
        message: `Started detached phux chat '${session}'${paneId ? ` (${paneId})` : ""}. Grab: phux attach ${session} | window: phux native attach ${nativeTarget}`,
      };
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
    context.keymap.layer(() => ({
      commands: [
        {
          id: "multiplayer.chat",
          title: "Open Multiplayer Party Chat",
          description: "Launch mp-outpost chat in a detached phux window (tmux/Omarchy fallback)",
          group: "Multiplayer",
          bind: "ctrl+shift+p",
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
  },
};

export default tuiPlugin;
