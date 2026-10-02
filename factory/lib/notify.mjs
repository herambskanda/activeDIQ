// macOS notifications for the CEO. A no-op elsewhere or when config.ceo.notify.macos is false.
import { execFile } from 'node:child_process';

/**
 * Show a macOS notification. Arguments reach AppleScript as argv, never interpolated into source.
 * @param {object} ctx
 * @param {{title: string, message: string}} note
 * @returns {boolean} whether a notification was attempted
 */
export function notify(ctx, { title, message }) {
  if (process.platform !== 'darwin' || !ctx.config?.ceo?.notify?.macos) return false;
  try {
    const child = execFile('osascript', [
      '-e', 'on run argv',
      '-e', 'display notification (item 1 of argv) with title (item 2 of argv)',
      '-e', 'end run',
      '--', String(message), String(title),
    ], { timeout: 5000 }, () => {});
    child.unref();
    return true;
  } catch {
    return false;
  }
}
