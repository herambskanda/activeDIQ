// Optional dispatcher knobs. config.json is authoritative; these are the defaults for keys it
// does not set (documented in README "Development").
const DEFAULTS = {
  poll_seconds: 2,
  persist_seconds: 5,
  shutdown_grace_seconds: 120,
  kill_grace_seconds: 30,
  launch_failure_backoff_minutes: 5,
  blocked_retriage_hours: 6,
};

/**
 * Read a dispatcher setting, falling back to its default.
 * @param {object} config
 * @param {keyof typeof DEFAULTS} key
 * @returns {number}
 */
export function setting(config, key) {
  return config.dispatcher?.[key] ?? DEFAULTS[key];
}
