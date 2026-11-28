"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vscode = require("vscode");

const SAFE_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function resolveBinaryPath(binary) {
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
    } catch {}
  }
  return binary;
}

function formatTerminalAddress(val) {
  if (typeof val === "number" && Number.isInteger(val) && val > 0) return `@${val}`;
  if (typeof val === "string") {
    const cleaned = val.trim();
    if (!cleaned) return null;
    if (/^\d+$/.test(cleaned)) return `@${cleaned}`;
    return cleaned;
  }
  return null;
}

function execCapture(binary, args, timeoutMs = 10000) {
  return new Promise((resolve) => {
    let settled = false;
    const child = spawn(binary, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const out = [];
    const err = [];
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGTERM");
      } catch {}
      resolve({ code: 124, stdout: "", stderr: "timed out" });
    }, timeoutMs);
    child.stdout.on("data", (c) => out.push(c));
    child.stderr.on("data", (c) => err.push(c));
    child.on("error", (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: e.code === "ENOENT" ? 127 : 1, stdout: "", stderr: e.message, notFound: e.code === "ENOENT" });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(out).toString("utf8").trim(),
        stderr: Buffer.concat(err).toString("utf8").trim(),
      });
    });
  });
}

function extractPaneId(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  if ("terminal_id" in payload) {
    const addr = formatTerminalAddress(payload.terminal_id);
    if (addr) return addr;
  }
  for (const k of ["terminal", "pane", "pane_id", "id"]) {
    const addr = formatTerminalAddress(payload[k]);
    if (addr) return addr;
  }
  for (const k of ["pane", "terminal", "seed", "result"]) {
    const nested = extractPaneId(payload[k]);
    if (nested) return nested;
  }
  return null;
}

function extractActiveTerminal(lsData, session) {
  if (!lsData || typeof lsData !== "object" || !Array.isArray(lsData.hosts)) return null;
  for (const host of lsData.hosts) {
    if (!host || !Array.isArray(host.sessions)) continue;
    const found = host.sessions.find((s) => s && s.name === session);
    if (found) {
      const addr = formatTerminalAddress(found.active_terminal);
      if (addr) return addr;
    }
  }
  return null;
}

function openOrFocusChatTerminal(outpostBinary) {
  const existing = vscode.window.terminals.find((t) => t.name === "Multiplayer Party Chat");
  if (existing) {
    existing.show(false);
    return existing;
  }
  const term = vscode.window.createTerminal({
    name: "Multiplayer Party Chat",
    shellPath: resolveBinaryPath(outpostBinary),
    shellArgs: ["chat"],
  });
  term.show(false);
  return term;
}

async function openDetachedPhuxWindow(outpostBinary, sessionName) {
  const session = SAFE_SESSION_RE.test(sessionName) ? sessionName : "multiplayer-chat";
  const phuxBin = resolveBinaryPath("phux");
  const resolvedOutpost = resolveBinaryPath(outpostBinary);
  const lsRes = await execCapture(phuxBin, ["ls", "--json"]);
  if (lsRes.notFound) {
    const choice = await vscode.window.showWarningMessage(
      "phux was not found on PATH. Open Multiplayer Party Chat in the integrated terminal instead?",
      "Open Integrated Terminal",
    );
    if (choice === "Open Integrated Terminal") {
      openOrFocusChatTerminal(resolvedOutpost);
    }
    return;
  }

  let existingFound = false;
  let existingRunning = false;
  let paneId = null;
  if (lsRes.code === 0 && lsRes.stdout) {
    try {
      const parsed = JSON.parse(lsRes.stdout);
      const found = (parsed.sessions || []).find((s) => s && s.name === session);
      if (found) {
        existingFound = true;
        existingRunning = Number(found.exec?.running ?? 0) + Number(found.exec?.starting ?? 0) > 0;
        if (existingRunning) {
          paneId = extractActiveTerminal(parsed, session);
        }
      }
    } catch {}
  }

  if (!existingRunning) {
    if (existingFound) {
      await execCapture(phuxBin, ["kill", "--yes", session]);
    }
    const created = await execCapture(phuxBin, ["new", "--json", "-s", session, "--", resolvedOutpost, "chat"], 15000);
    if (created.code !== 0) {
      if ((created.stdout || "").includes("spawn_failed") || (created.stderr || "").includes("spawn_failed")) {
        await execCapture(phuxBin, ["kill", "--yes", session]);
      }
      vscode.window.showErrorMessage(`Failed to start detached phux session '${session}': ${created.stderr || created.stdout || created.code}`);
      return;
    }
    if (created.stdout) {
      try {
        paneId = extractPaneId(JSON.parse(created.stdout));
      } catch {}
    }
  }

  const attachCmd = `phux attach ${session}`;
  const nativeCmd = paneId ? `phux native attach ${paneId}` : null;
  const actions = ["Attach in Terminal", "Copy phux attach", ...(nativeCmd ? ["Copy phux native"] : [])];
  const choice = await vscode.window.showInformationMessage(
    `Multiplayer Party Chat is running in detached phux session '${session}'${paneId ? ` (${paneId})` : ""}.`,
    ...actions,
  );
  if (choice === "Attach in Terminal") {
    const termName = `phux: ${session}`;
    const existingTerm = vscode.window.terminals.find((t) => t.name === termName);
    if (existingTerm) {
      existingTerm.show(false);
    } else {
      const term = vscode.window.createTerminal({
        name: termName,
        shellPath: phuxBin,
        shellArgs: ["attach", session],
      });
      term.show(false);
    }
  } else if (choice === "Copy phux attach") {
    await vscode.env.clipboard.writeText(attachCmd);
  } else if (choice === "Copy phux native" && nativeCmd) {
    await vscode.env.clipboard.writeText(nativeCmd);
  }
}

function activate(context) {
  const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusItem.text = "$(broadcast) Party Chat";
  statusItem.tooltip = "Open Multiplayer Party Chat (mp-outpost chat)";
  statusItem.command = "multiplayer.openPartyChat";
  statusItem.show();

  const getCfg = () => {
    const cfg = vscode.workspace.getConfiguration("multiplayer");
    return {
      outpostBinary: String(cfg.get("outpostBinary", "mp-outpost") || "mp-outpost").trim(),
      phuxSession: String(cfg.get("phuxSession", "multiplayer-chat") || "multiplayer-chat").trim(),
    };
  };

  context.subscriptions.push(
    statusItem,
    vscode.commands.registerCommand("multiplayer.openPartyChat", () => {
      const { outpostBinary } = getCfg();
      openOrFocusChatTerminal(outpostBinary);
    }),
    vscode.commands.registerCommand("multiplayer.openDetachedPhuxChat", async () => {
      const { outpostBinary, phuxSession } = getCfg();
      await openDetachedPhuxWindow(outpostBinary, phuxSession);
    }),
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
