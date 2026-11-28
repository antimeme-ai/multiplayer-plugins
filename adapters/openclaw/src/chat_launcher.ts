/**
 * Detached `phux` party chat launcher (with `tmux` / `omarchy-launch-tui` fallback)
 * for OpenClaw. Uses `spawn(..., { shell: false })` exclusively and refuses
 * secret tokens or `#fragment` URLs on process argv.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectForbiddenSecret } from "./security.ts";

export interface DetachedChatResult {
  ok: boolean;
  backend: "phux" | "tmux" | "omarchy-launch-tui" | "manual";
  session: string;
  paneId?: string;
  reused: boolean;
  attachCmd: string;
  nativeCmd?: string;
  message: string;
}

const DEFAULT_SESSION = "multiplayer-chat";
const SAFE_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_TARGET_RE = /^@?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

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
      resolve({
        code: err.code === "ENOENT" ? 127 : 1,
        stdout: "",
        stderr: err.message,
        notFound: err.code === "ENOENT",
      });
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

export function validateChatTarget(raw?: string): string | undefined {
  const cleaned = raw?.trim();
  if (!cleaned) return undefined;
  if (cleaned.startsWith("-")) {
    throw new Error("Refused chat target: value cannot start with '-'.");
  }
  if (cleaned.includes("#")) {
    throw new Error(
      "Refused #fragment invite URL on process argv: redeem fragment links directly via `mp-outpost join` in your terminal.",
    );
  }
  const secret = detectForbiddenSecret(cleaned);
  if (secret !== null) {
    throw new Error(`Refused chat target: detected forbidden secret material (${secret}).`);
  }
  if (!SAFE_TARGET_RE.test(cleaned)) {
    throw new Error("Chat target must be a @handle, room code, or numeric party ID.");
  }
  return cleaned;
}

export async function launchDetachedPartyChat(options?: {
  outpostBinary?: string;
  stateDir?: string;
  target?: string;
  session?: string;
  phuxBinary?: string;
  tmuxBinary?: string;
  omarchyTuiBinary?: string;
}): Promise<DetachedChatResult> {
  const session = (options?.session ?? DEFAULT_SESSION).trim();
  if (!SAFE_SESSION_RE.test(session)) {
    throw new Error(`Invalid session name '${session}'.`);
  }
  const cleanTarget = validateChatTarget(options?.target);
  const resolvedOutpost = resolveBinaryPath(options?.outpostBinary?.trim() || "mp-outpost");
  const outpostCmd = [resolvedOutpost];
  if (options?.stateDir?.trim()) {
    outpostCmd.push("--state-dir", options.stateDir.trim());
  }
  outpostCmd.push("chat");
  if (cleanTarget) outpostCmd.push(cleanTarget);

  const phuxBin = resolveBinaryPath(options?.phuxBinary ?? process.env.PHUX_BIN?.trim() ?? "phux");
  const lsRes = await execCapture(phuxBin, ["ls", "--json"]);
  if (!lsRes.notFound) {
    let existingRunning = false;
    let existingFound = false;
    let existingTerminal: string | undefined;
    if (lsRes.code === 0 && lsRes.stdout) {
      try {
        const parsed = JSON.parse(lsRes.stdout) as {
          sessions?: Array<{ name?: string; exec?: { running?: number; starting?: number } }>;
        };
        const found = parsed.sessions?.find((s) => s?.name === session);
        if (found) {
          existingFound = true;
          const active = Number(found.exec?.running ?? 0) + Number(found.exec?.starting ?? 0);
          existingRunning = active > 0;
          if (existingRunning) existingTerminal = extractActiveTerminal(parsed, session);
        }
      } catch {
        // Proceed to create
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
        message: `Party chat is already running in detached phux session '${session}'${existingTerminal ? ` (${existingTerminal})` : ""}. Grab it with: phux attach ${session}${nativeCmd ? ` (or window: ${nativeCmd})` : ""}`,
      };
    }

    if (existingFound) {
      await execCapture(phuxBin, ["kill", "--yes", session]);
    }

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
        message: `Started detached phux party chat in '${session}'${paneId ? ` (${paneId})` : ""}. Grab it with: phux attach ${session}${nativeCmd ? ` (or window: ${nativeCmd})` : ""}`,
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
        message: `Party chat is already running in detached tmux session '${session}'. Grab it with: tmux attach -t ${session}`,
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
        message: `Started detached tmux party chat in '${session}'. Grab it with: tmux attach -t ${session}`,
      };
    }
  }

  const omarchyBin = options?.omarchyTuiBinary ?? "omarchy-launch-tui";
  const checkOmarchy = await execCapture("which", [omarchyBin], 3_000);
  if (checkOmarchy.code === 0) {
    const child = spawn(omarchyBin, outpostCmd, {
      shell: false,
      detached: true,
      stdio: "ignore",
    });
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
    message: `Neither phux, tmux, nor omarchy-launch-tui found. Run in another terminal: ${outpostCmd.join(" ")}`,
  };
}
