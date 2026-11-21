// How many done tickets one gate run judges together (merge plan step 4.2).
//
// `pre_merge.train_size` is a fixed number. With `pre_merge.train_size_max` set (2 or more) the size is
// chosen from how the last gate verdicts went instead: big batches only pay while most tickets pass,
// because every failure in a batch costs an extra run (see culprit.mjs). The pass rate is read from the
// factory's own events, so it survives restarts and needs no new state.
//
//   pass rate of the last 20 verdicts >= 0.85  -> train_size_max
//                                     >= 0.60  -> 2 (or the max, if lower)
//                                     below    -> 1
// Fewer than MIN_SAMPLES verdicts on record: 2 (a cautious start that also builds the record).

import { readRecentEvents } from './store.mjs';

export const HISTORY = 20;
export const MIN_SAMPLES = 10;
export const HIGH_RATE = 0.85;
export const MID_RATE = 0.6;
// Files whose change can break any other ticket in the same run: such a ticket is always gated alone.
const SOLO = [/^go\.(mod|sum)$/, /^Makefile$/, /\.mk$/, /^tools\/ci\//];

/**
 * Pass/fail of the most recent per-ticket gate verdicts, oldest first.
 * A pass is "pre-merge gate passed", a fail is "merge refused by the pre-merge gate". A refusal for the
 * migration-numbering check is main's collision, not the ticket's mistake, so it is not counted.
 * @param {{kind?: string, text?: string}[]} events newest first, as `readRecentEvents` returns them
 * @param {number} [limit]
 * @returns {boolean[]}
 */
export function verdictHistory(events, limit = HISTORY) {
  const out = [];
  for (const e of events) {
    if (e.kind !== 'ticket' || typeof e.text !== 'string') continue;
    if (/pre-merge gate passed/.test(e.text)) out.push(true);
    else if (/merge refused by the pre-merge gate/.test(e.text) && !/migration[- ]number/i.test(e.text)) out.push(false);
    if (out.length >= limit) break;
  }
  return out.reverse();
}

/**
 * @param {number} max `pre_merge.train_size_max`
 * @param {boolean[]} history oldest first
 * @returns {number}
 */
export function chooseTrainSize(max, history) {
  if (!Number.isInteger(max) || max < 2) return 1;
  const recent = history.slice(-HISTORY);
  if (recent.length < MIN_SAMPLES) return Math.min(2, max);
  const rate = recent.filter(Boolean).length / recent.length;
  if (rate >= HIGH_RATE) return max;
  if (rate >= MID_RATE) return Math.min(2, max);
  return 1;
}

/** The train size to use right now. `train_size` is used as is unless `train_size_max` is set. */
export function effectiveTrainSize(ctx, settings) {
  if (!settings.train_size_max || settings.train_size_max < 2) return settings.train_size;
  return chooseTrainSize(settings.train_size_max, verdictHistory(readRecentEvents(ctx, 2000)));
}

/** True when a ticket changing these files must be gated alone. */
export function mustGoAlone(files) {
  return files.some((f) => SOLO.some((re) => re.test(f)));
}
