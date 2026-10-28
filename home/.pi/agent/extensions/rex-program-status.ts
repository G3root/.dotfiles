/**
 * Rex Program Status (OSC 7501)
 *
 * Tells Rex what this Pi session is doing, so Rex can show it in tab headers,
 * the session picker, and Lua scripts. States follow the Program Status
 * Protocol: idle, working, blocked, done.
 *
 *   idle      at rest, waiting for the first prompt
 *   working   a turn is running (msg names the current tool)
 *   blocked   a dialog is open (confirm -> permission, else question)
 *   done      the run finished and nothing will continue automatically
 *
 * Unrelated to herdr-agent-state.ts: that one talks to Herdr's socket, this
 * one writes an escape sequence to the terminal Rex emulates.
 * https://www.superlogical.com/rex/docs/build/program-status
 *
 * @ts-nocheck
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const APP = "pi";
const TITLE = "Pi";
const ESC = "\x1b";

type State = "idle" | "working" | "blocked" | "done" | "clear";
type Kind = "permission" | "question";

type Report = { state: State; kind?: Kind; msg?: string };

/** True only where an escape sequence reaches Rex and cannot corrupt output. */
function enabled(): boolean {
  return process.env.TERM_PROGRAM === "rex" && process.stdout.isTTY === true;
}

/** Free-text values are single-line base64 and must hold no control characters. */
function encodeText(value: string, limit: number): string {
  const clean = value
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .slice(0, limit)
    .trim();
  return Buffer.from(clean, "utf8").toString("base64").replace(/=+$/, "");
}

function write(report: Report): void {
  const pairs = [`state=${report.state}`];
  if (report.state === "blocked" && report.kind) pairs.push(`kind=${report.kind}`);
  pairs.push(`app=${APP}`);
  if (report.state !== "clear") {
    pairs.push(`title=${encodeText(TITLE, 192)}`);
    if (report.msg) pairs.push(`msg=${encodeText(report.msg, 2000)}`);
  }
  process.stdout.write(`${ESC}]7501;${pairs.join(":")}${ESC}\\`);
}

export default function (pi: ExtensionAPI) {
  if (!enabled()) return;

  let active = false; // a turn is running
  let settled = false; // a run finished; nothing continues on its own
  let workingMsg: string | undefined;
  let blockedCount = 0;
  let blockedKind: Kind = "question";
  let blockedMsg: string | undefined;
  let lastKey: string | undefined;

  function current(): Report {
    if (blockedCount > 0) {
      return { state: "blocked", kind: blockedKind, msg: blockedMsg };
    }
    if (active) return { state: "working", msg: workingMsg };
    return settled ? { state: "done", msg: "ready for input" } : { state: "idle" };
  }

  function publish(force = false): void {
    const report = current();
    const key = `${report.state}|${report.kind ?? ""}|${report.msg ?? ""}`;
    if (!force && key === lastKey) return;
    lastKey = key;
    write(report);
  }

  pi.on("session_start", async (_event, ctx) => {
    // TUI only: RPC/JSON/print modes have no terminal that Rex can read.
    if (ctx?.mode !== "tui") return;
    active = ctx?.isIdle?.() === false;
    settled = false;
    publish(true);
  });

  pi.on("agent_start", () => {
    active = true;
    settled = false;
    workingMsg = "thinking";
    publish();
  });

  pi.on("turn_start", () => {
    active = true;
    settled = false;
    publish();
  });

  pi.on("tool_execution_start", (event) => {
    active = true;
    settled = false;
    workingMsg = event?.toolName ? `running ${event.toolName}` : "working";
    publish();
  });

  pi.on("ui_prompt_start", (event) => {
    blockedCount += 1;
    blockedKind = event?.kind === "confirm" ? "permission" : "question";
    blockedMsg =
      event?.title ??
      (blockedKind === "permission" ? "waiting for approval" : "waiting for an answer");
    publish(true);
  });

  pi.on("ui_prompt_end", () => {
    blockedCount = Math.max(0, blockedCount - 1);
    if (blockedCount === 0) {
      blockedMsg = undefined;
      blockedKind = "question";
    }
    publish(true);
  });

  pi.on("agent_settled", (_event, ctx) => {
    if (ctx?.isIdle?.() !== true) return;
    active = false;
    settled = true;
    workingMsg = undefined;
    publish(true);
  });

  pi.on("session_shutdown", () => {
    write({ state: "clear" });
  });
}
