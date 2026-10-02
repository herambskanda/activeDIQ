// Parsing a worker's `--output-format stream-json` log: live context usage and activity for the
// dispatcher, the final result, and a readable tail for the board.
import { StringDecoder } from 'node:string_decoder';

const RATE_LIMIT = /rate.?limit|usage limit|overloaded|\b429\b/i;

const oneLine = (s) => String(s).replace(/\s+/g, ' ').trim();
const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/**
 * A short, single-line description of a tool call's input.
 * @param {string} name tool name
 * @param {Record<string, unknown>|undefined} input
 */
export function summarizeToolInput(name, input) {
  const i = input ?? {};
  const pick = i.command ?? i.file_path ?? i.path ?? i.pattern ?? i.description ?? i.prompt ?? i.url ?? i.query
    ?? Object.values(i).find((v) => typeof v === 'string');
  return clip(oneLine(pick ?? ''), 100);
}

/**
 * The last `RESULT:` line of a worker's final message.
 * @param {string|undefined|null} text
 * @returns {string|null}
 */
export function findResultLine(text) {
  const lines = String(text ?? '').split(/\r?\n/).filter((l) => l.startsWith('RESULT:'));
  return lines.length ? lines.at(-1).trim() : null;
}

/**
 * The keyword of a RESULT line: advanced, rejected, blocked, handoff, failed (or null).
 * @param {string|null} resultLine
 */
export function resultKeyword(resultLine) {
  const m = /^RESULT:\s*(advanced|rejected|blocked|handoff|failed)\b/i.exec(resultLine ?? '');
  return m ? m[1].toLowerCase() : null;
}

/**
 * Whether a finished run failed because of a usage / rate limit.
 * @param {{result?: {is_error?: boolean, result?: string}|null, stderr?: string}} input
 */
export function detectRateLimit({ result = null, stderr = '' }) {
  if (result && !result.is_error) return false;
  return RATE_LIMIT.test(result?.result ?? '') || RATE_LIMIT.test(stderr);
}

function activityOf(content) {
  const tool = [...content].reverse().find((c) => c?.type === 'tool_use');
  if (tool) return `${tool.name} · ${summarizeToolInput(tool.name, tool.input)}`;
  const text = [...content].reverse().find((c) => c?.type === 'text' && c.text?.trim());
  return text ? clip(oneLine(text.text), 120) : null;
}

/**
 * Incremental parser for a growing stream-json log. Feed it chunks; read `state`.
 */
export class LogScanner {
  constructor() {
    this.decoder = new StringDecoder('utf8');
    this.carry = '';
    this.state = {
      session_id: null, model: null, context_tokens: 0, peak_context_tokens: 0,
      last_activity: null, result: null,
    };
  }

  /**
   * Consume more log bytes.
   * @param {Buffer|string} chunk
   * @returns {boolean} whether anything the dispatcher records changed
   */
  push(chunk) {
    const text = this.carry + (typeof chunk === 'string' ? chunk : this.decoder.write(chunk));
    const lines = text.split('\n');
    this.carry = lines.pop();
    let changed = false;
    for (const line of lines) changed = this.#line(line) || changed;
    return changed;
  }

  /**
   * Process a final line that has no trailing newline (call once the process has exited).
   * @returns {boolean} whether anything changed
   */
  flush() {
    const rest = this.carry + this.decoder.end();
    this.carry = '';
    return this.#line(rest);
  }

  #line(line) {
    if (!line.trim()) return false;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return false; // not JSON (a stray warning): ignore
    }
    const s = this.state;
    if (msg.type === 'system' && msg.subtype === 'init') {
      s.session_id = msg.session_id ?? s.session_id;
      s.model = msg.model ?? s.model;
      return true;
    }
    if (msg.type === 'assistant' && msg.message) {
      const content = Array.isArray(msg.message.content) ? msg.message.content : [];
      const u = msg.message.usage;
      if (u && !msg.parent_tool_use_id) {
        s.context_tokens = (u.input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0);
        s.peak_context_tokens = Math.max(s.peak_context_tokens, s.context_tokens);
      }
      s.last_activity = activityOf(content) ?? s.last_activity;
      s.session_id ??= msg.session_id ?? null;
      return true;
    }
    if (msg.type === 'result') {
      s.result = parseResultMessage(msg);
      s.session_id = msg.session_id ?? s.session_id;
      return true;
    }
    return false;
  }
}

/**
 * Reduce a stream-json `result` message to the fields the dispatcher stores.
 * @param {object} msg
 */
export function parseResultMessage(msg) {
  const text = typeof msg.result === 'string' ? msg.result : '';
  return {
    is_error: Boolean(msg.is_error),
    subtype: msg.subtype ?? null,
    num_turns: msg.num_turns ?? 0,
    total_cost_usd: msg.total_cost_usd ?? 0,
    session_id: msg.session_id ?? null,
    result: text,
    result_line: findResultLine(text),
  };
}

/**
 * Turn the tail of a stream-json log into readable lines for the board:
 * `assistant: …`, `tool: Bash · <command>`, `result: …`.
 * @param {string} text log text (a complete-line tail is fine)
 * @param {number} maxLines
 * @returns {string[]}
 */
export function readableLines(text, maxLines) {
  const out = [];
  for (const raw of text.split('\n')) {
    if (!raw.trim()) continue;
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      continue;
    }
    if (msg.type === 'system' && msg.subtype === 'init') {
      out.push(`system: session started${msg.model ? ` (${msg.model})` : ''}`);
    } else if (msg.type === 'assistant') {
      for (const block of Array.isArray(msg.message?.content) ? msg.message.content : []) {
        if (block?.type === 'text' && block.text?.trim()) out.push(`assistant: ${clip(oneLine(block.text), 400)}`);
        else if (block?.type === 'tool_use') out.push(`tool: ${block.name} · ${summarizeToolInput(block.name, block.input)}`);
      }
    } else if (msg.type === 'result') {
      out.push(`result: ${msg.is_error ? '[error] ' : ''}${clip(oneLine(msg.result ?? msg.subtype ?? ''), 400)}`);
    }
  }
  return out.slice(-maxLines);
}
