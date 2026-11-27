/**
 * Detached `phux` party chat launcher (with `tmux` / `omarchy-launch-tui` fallback)
 * for OpenClaw. Uses `spawn(..., { shell: false })` exclusively and refuses
 * secret tokens or `#fragment` URLs on process argv.
 */

import { spawn } from "node:child_process";
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

function extractPaneId(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const obj = payload as Record<string, unknown>;
  for (const k of ["terminal", "pane", "pane_id", "id"]) {
    if (typeof obj[k] === "string" && (obj[k] as string).trim()) {
      return (obj[k] as string).trim();
    }
  }
  for (const k of ["pane", "terminal", "seed", "result"]) {
    const nested = extractPaneId(obj[k]);
    if (nested) return nested;
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
  const outpostCmd = [options?.outpostBinary?.trim() || "mp-outpost", "chat"];
  if (cleanTarget) outpostCmd.push(cleanTarget);

  const phuxBin = options?.phuxBinary ?? process.env.PHUX_BIN?.trim() ?? "phux";
  const lsRes = await execCapture(phuxBin, ["ls", "--json"]);
  if (!lsRes.notFound) {
    let existingRunning = false;
    let existingFound = false;
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
        }
      } catch {
        // Proceed to create
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
        message: `Party chat is already running in detached phux session '${session}'. Grab it with: phux attach ${session}`,
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
      const nativeTarget = paneId ?? `${session}:0.0`;
      return {
        ok: true,
        backend: "phux",
        session,
        ...(paneId ? { paneId } : {}),
        reused: false,
        attachCmd: `phux attach ${session}`,
        nativeCmd: `phux native attach ${nativeTarget}`,
        message: `Started detached phux party chat in '${session}'${paneId ? ` (${paneId})` : ""}. Grab it with: phux attach ${session} (or window: phux native attach ${nativeTarget})`,
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
