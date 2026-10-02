import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  LogScanner, detectRateLimit, findResultLine, parseResultMessage, readableLines, resultKeyword, summarizeToolInput,
} from '../lib/runlog.mjs';
import { FIXTURES } from './helpers.mjs';

const success = fs.readFileSync(path.join(FIXTURES, 'stream-success.jsonl'), 'utf8');
const limited = fs.readFileSync(path.join(FIXTURES, 'stream-ratelimit.jsonl'), 'utf8');

test('the scanner extracts session, model, context size, activity and the result', () => {
  const scanner = new LogScanner();
  assert.equal(scanner.push(success), true);
  const s = scanner.state;
  assert.equal(s.session_id, 's-1');
  assert.equal(s.model, 'claude-sonnet-5-5');
  // latest main-thread assistant message: input 2 + cache_creation 100 + cache_read 8549
  assert.equal(s.context_tokens, 8651);
  assert.equal(s.peak_context_tokens, 8651, 'the subagent message (99k) is ignored');
  assert.equal(s.last_activity, 'All acceptance criteria are met and the tests pass. Done.');
  assert.deepEqual(s.result, {
    is_error: false, subtype: 'success', num_turns: 3, total_cost_usd: 0.07, session_id: 's-1',
    result: 'Implemented the builder.\nRESULT: advanced — filter builder done, 14 tests',
    result_line: 'RESULT: advanced — filter builder done, 14 tests',
  });
});

test('context size is the latest message, the peak is the maximum', () => {
  const msg = (input, create, read) => `${JSON.stringify({ type: 'assistant', message: { content: [], usage: { input_tokens: input, cache_creation_input_tokens: create, cache_read_input_tokens: read } } })}\n`;
  const scanner = new LogScanner();
  scanner.push(msg(1, 0, 9000));
  scanner.push(msg(1, 0, 4000));
  assert.deepEqual([scanner.state.context_tokens, scanner.state.peak_context_tokens], [4001, 9001]);
});

test('the activity is the last tool call of a message', () => {
  const scanner = new LogScanner();
  scanner.push(`${JSON.stringify({ type: 'assistant', message: { content: [
    { type: 'text', text: 'looking' }, { type: 'tool_use', name: 'Read', input: { file_path: '/a/b.md' } },
  ], usage: { input_tokens: 1 } } })}\n`);
  assert.equal(scanner.state.last_activity, 'Read · /a/b.md');
});

test('chunks may split lines and multi-byte characters anywhere', () => {
  const bytes = Buffer.from(success.replace('builder', 'bü🙂lder'), 'utf8');
  const scanner = new LogScanner();
  for (let i = 0; i < bytes.length; i += 7) scanner.push(bytes.subarray(i, i + 7));
  scanner.flush();
  assert.match(scanner.state.result.result, /bü🙂lder/);
  assert.equal(scanner.state.context_tokens, 8651);
});

test('garbage lines and a final line without newline are handled', () => {
  const scanner = new LogScanner();
  assert.equal(scanner.push('warning: not json\n{"also": broken}\n'), false);
  assert.equal(scanner.state.result, null);
  scanner.push('{"type":"result","is_error":false,"result":"ok\\nRESULT: blocked — x","session_id":"z"}');
  assert.equal(scanner.state.result, null, 'incomplete until flushed');
  assert.equal(scanner.flush(), true);
  assert.equal(scanner.state.result.result_line, 'RESULT: blocked — x');
  assert.equal(scanner.state.session_id, 'z');
});

test('RESULT lines: the last one wins; keywords are normalised', () => {
  assert.equal(findResultLine('a\nRESULT: advanced — one\nthinking\nRESULT: rejected — two\n'), 'RESULT: rejected — two');
  assert.equal(findResultLine('no result here'), null);
  assert.equal(findResultLine(undefined), null);
  assert.deepEqual(['RESULT: advanced — x', 'RESULT: REJECTED — x', 'RESULT: handoff', 'RESULT: failed — y', 'RESULT: blocked — z', 'RESULT: weird', null].map(resultKeyword),
    ['advanced', 'rejected', 'handoff', 'failed', 'blocked', null, null]);
});

test('parseResultMessage tolerates missing fields', () => {
  assert.deepEqual(parseResultMessage({ type: 'result' }), {
    is_error: false, subtype: null, num_turns: 0, total_cost_usd: 0, session_id: null, result: '', result_line: null,
  });
});

test('rate-limit detection looks at error results and stderr only', () => {
  const scanner = new LogScanner();
  scanner.push(limited);
  assert.equal(detectRateLimit({ result: scanner.state.result }), true);
  assert.equal(detectRateLimit({ result: null, stderr: 'Error: 429 Too Many Requests' }), true);
  assert.equal(detectRateLimit({ result: null, stderr: 'API is Overloaded, retry' }), true);
  assert.equal(detectRateLimit({ result: null, stderr: 'rate-limit exceeded' }), true);
  assert.equal(detectRateLimit({ result: null, stderr: 'segfault' }), false);
  assert.equal(detectRateLimit({ result: { is_error: false, result: 'we handled the usage limit docs' } }), false, 'a successful run is never a rate limit');
  assert.equal(detectRateLimit({ result: { is_error: true, result: 'tests failed at line 4290' } }), false, '4290 is not 429');
});

test('readableLines turns the stream into short labelled lines', () => {
  const lines = readableLines(success, 50);
  assert.deepEqual(lines, [
    'system: session started (claude-sonnet-5-5)',
    "assistant: I'll start by reading the ticket.",
    'tool: Bash · factory/bin/factory ticket show T-0004',
    'tool: Read · /repo/knowledge/product/specs/ldap.md',
    'assistant: subagent chatter',
    'assistant: All acceptance criteria are met and the tests pass. Done.',
    'result: Implemented the builder. RESULT: advanced — filter builder done, 14 tests',
  ]);
  assert.deepEqual(readableLines(success, 2), lines.slice(-2));
  assert.deepEqual(readableLines('not json\n\n{"type":"x"}\n', 10), []);
});

test('readableLines marks error results and clips very long text', () => {
  const long = JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text: 'x'.repeat(1000) }] } });
  assert.ok(readableLines(long, 5)[0].length < 420);
  assert.match(readableLines(limited, 5).at(-1), /^result: \[error\] You've hit your usage limit/);
});

test('summarizeToolInput prefers command, then paths, then any string; clips at 100', () => {
  assert.equal(summarizeToolInput('Bash', { command: 'ls\n  -la' }), 'ls -la');
  assert.equal(summarizeToolInput('Read', { file_path: '/x' }), '/x');
  assert.equal(summarizeToolInput('Grep', { pattern: 'foo', path: '/y' }), '/y');
  assert.equal(summarizeToolInput('Odd', { n: 1, s: 'str' }), 'str');
  assert.equal(summarizeToolInput('None', undefined), '');
  assert.equal(summarizeToolInput('Bash', { command: 'a'.repeat(300) }).length, 100);
});
