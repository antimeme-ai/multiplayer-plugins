/**
 * Bounded, shell-free `mp-outpost` subprocess runner for the OpenClaw plugin.
 */

import { spawn } from "node:child_process";
import { redactUrlFragments } from "./security.ts";

export interface OutpostRunnerOptions {
  binary: string;
  stateDir?: string;
}

export async function runOutpostJson(
  opts: OutpostRunnerOptions,
  args: string[],
  options?: {
    timeoutMs?: number;
    stdinText?: string;
    stdinBytes?: Buffer;
    signal?: AbortSignal;
  },
): Promise<unknown> {
  if (options?.signal?.aborted) {
    throw new Error("mp-outpost invocation aborted");
  }

  const timeoutMs = options?.timeoutMs ?? 15_000;
  const argv: string[] = [];
  if (opts.stateDir) {
    argv.push("--state-dir", opts.stateDir);
  }
  argv.push("--json", ...args);

  return await new Promise<unknown>((resolve, reject) => {
    const child = spawn(opts.binary, argv, {
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    const maxBytes = 2 * 1024 * 1024;

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      options?.signal?.removeEventListener("abort", onAbort);
      fn();
    };

    const killChild = (): void => {
      try {
        child.kill("SIGTERM");
      } catch {
        // already exited
      }
      const hardKill = setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGKILL");
          }
        } catch {
          // already exited
        }
      }, 2_000);
      hardKill.unref?.();
    };

    const onAbort = (): void => {
      killChild();
      finish(() => reject(new Error("mp-outpost invocation aborted")));
    };

    timer = setTimeout(() => {
      killChild();
      finish(() => reject(new Error(`mp-outpost timed out after ${timeoutMs}ms`)));
    }, timeoutMs);

    if (options?.signal) {
      if (options.signal.aborted) {
        onAbort();
        return;
      }
      options.signal.addEventListener("abort", onAbort, { once: true });
    }

    child.stdin.on("error", () => {
      // Ignore EPIPE when the child exits early before consuming stdin.
    });

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxBytes) {
        killChild();
        finish(() => reject(new Error(`mp-outpost stdout exceeded ${maxBytes} bytes limit`)));
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr.on("data", (chunk: Buffer) => {
      if (stderrChunks.length < 16) {
        stderrChunks.push(chunk);
      }
    });

    child.on("error", (err) => {
      finish(() => reject(new Error(redactUrlFragments(`mp-outpost spawn failed: ${err.message}`))));
    });

    child.on("close", (code) => {
      const stdout = Buffer.concat(stdoutChunks).toString("utf8").trim();
      const stderr = redactUrlFragments(Buffer.concat(stderrChunks).toString("utf8").trim());
      if (code !== 0) {
        const msg = stderr || redactUrlFragments(stdout.slice(0, 200)) || `exit code ${code}`;
        finish(() => reject(new Error(`mp-outpost failed (${code}): ${msg}`)));
        return;
      }
      if (!stdout) {
        finish(() => reject(new Error("mp-outpost returned empty JSON output")));
        return;
      }
      try {
        const parsed = JSON.parse(stdout);
        finish(() => resolve(parsed));
      } catch (err) {
        finish(() => reject(new Error(`mp-outpost returned invalid JSON: ${(err as Error).message}`)));
      }
    });

    if (options?.stdinBytes !== undefined) {
      child.stdin.end(options.stdinBytes);
    } else if (options?.stdinText !== undefined) {
      child.stdin.end(options.stdinText, "utf8");
    } else {
      child.stdin.end();
    }
  });
}
