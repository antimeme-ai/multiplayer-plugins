"use strict";

const { spawn } = require("node:child_process");
const vscode = require("vscode");

const SAFE_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

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
  for (const k of ["terminal", "pane", "pane_id", "id"]) {
    if (typeof payload[k] === "string" && payload[k].trim()) return payload[k].trim();
  }
  for (const k of ["pane", "terminal", "seed", "result"]) {
    const nested = extractPaneId(payload[k]);
    if (nested) return nested;
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
    shellPath: outpostBinary,
    shellArgs: ["chat"],
  });
  term.show(false);
  return term;
}

async function openDetachedPhuxWindow(outpostBinary, sessionName) {
  const session = SAFE_SESSION_RE.test(sessionName) ? sessionName : "multiplayer-chat";
  const lsRes = await execCapture("phux", ["ls", "--json"]);
  if (lsRes.notFound) {
    const choice = await vscode.window.showWarningMessage(
      "phux was not found on PATH. Open Multiplayer Party Chat in the integrated terminal instead?",
      "Open Integrated Terminal",
    );
    if (choice === "Open Integrated Terminal") {
      openOrFocusChatTerminal(outpostBinary);
    }
    return;
  }

  let existingFound = false;
  let existingRunning = false;
  if (lsRes.code === 0 && lsRes.stdout) {
    try {
      const parsed = JSON.parse(lsRes.stdout);
      const found = (parsed.sessions || []).find((s) => s && s.name === session);
      if (found) {
        existingFound = true;
        existingRunning = Number(found.exec?.running ?? 0) + Number(found.exec?.starting ?? 0) > 0;
      }
    } catch {}
  }

  let paneId = null;
  if (!existingRunning) {
    if (existingFound) {
      await execCapture("phux", ["kill", "--yes", session]);
    }
    const created = await execCapture("phux", ["new", "--json", "-s", session, "--", outpostBinary, "chat"], 15000);
    if (created.code !== 0) {
      vscode.window.showErrorMessage(`Failed to start detached phux session '${session}': ${created.stderr || created.code}`);
      return;
    }
    if (created.stdout) {
      try {
        paneId = extractPaneId(JSON.parse(created.stdout));
      } catch {}
    }
  }

  const attachCmd = `phux attach ${session}`;
  const nativeTarget = paneId || `${session}:0.0`;
  const choice = await vscode.window.showInformationMessage(
    `Multiplayer Party Chat is running in detached phux session '${session}'.`,
    "Attach in Terminal",
    "Copy phux attach",
    "Copy phux native",
  );
  if (choice === "Attach in Terminal") {
    const term = vscode.window.createTerminal({
      name: `phux: ${session}`,
      shellPath: "phux",
      shellArgs: ["attach", session],
    });
    term.show(false);
  } else if (choice === "Copy phux attach") {
    await vscode.env.clipboard.writeText(attachCmd);
  } else if (choice === "Copy phux native") {
    await vscode.env.clipboard.writeText(`phux native attach ${nativeTarget}`);
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
