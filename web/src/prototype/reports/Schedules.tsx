import { useId, useMemo, useState } from "react";

import { type Column, DataGrid, type DataGridColumn, Table } from "../../ds/components";
import type { RecipientState, SchedRecipient, Schedule } from "./fixtures";

const STATE_LABEL: Record<RecipientState, string> = {
  sent: "✓ Sent",
  queued: "◷ Queued",
  failed: "⚠ Failed",
  "gave-up": "✕ Given up",
};
const STATE_TONE: Record<RecipientState, string> = {
  sent: "ok",
  queued: "muted",
  failed: "crit",
  "gave-up": "crit",
};
const TONE_GLYPH = { ok: "✓", muted: "○", warn: "⏸", crit: "⚠" } as const;

function failedCount(s: Schedule): number {
  return s.recipients.filter((r) => r.state === "failed").length;
}

const scheduleColumns = (onOpen: (id: string) => void): DataGridColumn<Schedule>[] => [
  {
    key: "schedule",
    header: "Schedule",
    width: 44,
    title: (s) => `${s.name}: ${s.report}`,
    cell: (s) => (
      <>
        <button type="button" className="rp__link" onClick={() => onOpen(s.id)}>
          {s.name}
        </button>
        <span className="rp__subinline">{s.report}</span>
      </>
    ),
  },
  { key: "when", header: "When", width: 24, cell: (s) => s.when },
  { key: "next", header: "Next run", width: 24, cell: (s) => s.next },
  { key: "owner", header: "Owner", width: 16, cell: (s) => s.owner },
  {
    key: "recipients",
    header: "Recipients",
    width: 20,
    title: (s) => `${s.recipients.length} recipients, ${failedCount(s)} failed`,
    cell: (s) => (
      <>
        {s.recipients.length}
        {failedCount(s) > 0 ? (
          <span className="chip chip--crit">⚠ {failedCount(s)} failed</span>
        ) : null}
      </>
    ),
  },
  {
    key: "last",
    header: "Last run",
    width: 26,
    title: (s) => s.last,
    cell: (s) => (
      <span className={`chip chip--${s.lastTone}`}>
        {TONE_GLYPH[s.lastTone]} {s.last}
      </span>
    ),
  },
];

export function needsAttention(s: Schedule): boolean {
  return s.lastTone === "crit" || s.lastTone === "warn" || s.state === "paused";
}

export function Schedules(props: {
  readonly schedules: readonly Schedule[];
  readonly open: string | null;
  readonly onOpen: (id: string | null) => void;
  readonly onChange: (next: Schedule[], note: string) => void;
}) {
  const { schedules, open, onOpen, onChange } = props;
  const [filter, setFilter] = useState<"all" | "attention" | "paused">("all");
  const [picked, setPicked] = useState<string[]>([]);
  const [confirm, setConfirm] = useState<"pause" | "resume" | null>(null);
  const bulkId = useId();

  const shown = schedules.filter((s) =>
    filter === "all" ? true : filter === "paused" ? s.state === "paused" : needsAttention(s),
  );
  const columns = useMemo(() => scheduleColumns(onOpen), [onOpen]);
  const pickedSet = useMemo(() => new Set(picked), [picked]);
  const attention = schedules.filter(needsAttention).length;
  const pickedSchedules = schedules.filter((s) => picked.includes(s.id));
  const detail = schedules.find((s) => s.id === open) ?? null;

  const apply = (kind: "pause" | "resume") => {
    const target = pickedSchedules.filter((s) =>
      kind === "pause" ? s.state === "active" : s.state === "paused",
    );
    onChange(
      schedules.map((s) =>
        target.some((t) => t.id === s.id)
          ? kind === "pause"
            ? {
                ...s,
                state: "paused" as const,
                next: "Paused",
                last: "Paused by you",
                lastTone: "warn" as const,
                pausedWhy: "Paused by you. Nothing is sent until you resume it.",
              }
            : {
                ...s,
                state: "active" as const,
                next: "Next run on the schedule",
                last: "Resumed by you",
                lastTone: "muted" as const,
                pausedWhy: undefined,
              }
          : s,
      ),
      `${kind === "pause" ? "Paused" : "Resumed"} ${target.length} schedule${target.length === 1 ? "" : "s"}.`,
    );
    setConfirm(null);
    setPicked([]);
  };

  return (
    <>
      <div className="pt__head">
        <div>
          <h1>Schedules</h1>
          <p className="pt__sub">
            {schedules.length} schedules · {attention} need attention · each runs as its owner with
            the owner’s access at that moment.
          </p>
        </div>
      </div>
      <div className="rp__filters" role="radiogroup" aria-label="Show">
        {(
          [
            ["all", `All ${schedules.length}`],
            ["attention", `Needs attention ${attention}`],
            ["paused", `Paused ${schedules.filter((s) => s.state === "paused").length}`],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="radio"
            aria-checked={filter === id}
            className={`rp__seg${filter === id ? " rp__seg--on" : ""}`}
            onClick={() => setFilter(id)}
          >
            {label}
          </button>
        ))}
      </div>
      {picked.length > 0 ? (
        <div className="rp__bulk" role="region" aria-label="Selected schedules" id={bulkId}>
          {confirm === null ? (
            <>
              <strong>{picked.length} selected</strong>
              <button type="button" className="btn" onClick={() => setConfirm("pause")}>
                Pause
              </button>
              <button type="button" className="btn" onClick={() => setConfirm("resume")}>
                Resume
              </button>
              <button type="button" className="btn" onClick={() => setPicked([])}>
                Clear selection
              </button>
            </>
          ) : (
            <>
              <span>
                {confirm === "pause"
                  ? `Pause ${pickedSchedules.filter((s) => s.state === "active").length} active schedule(s)? Nothing is sent until they are resumed. Already paused ones are skipped.`
                  : `Resume ${pickedSchedules.filter((s) => s.state === "paused").length} paused schedule(s)? They run at their next due time, using their owner’s current access. Others are skipped.`}
              </span>
              <button type="button" className="btn btn--primary" onClick={() => apply(confirm)}>
                {confirm === "pause" ? "Pause" : "Resume"}
              </button>
              <button type="button" className="btn" onClick={() => setConfirm(null)}>
                Cancel
              </button>
            </>
          )}
        </div>
      ) : null}

      {shown.length === 0 ? (
        <div className="diq-state">
          <p className="diq-state__title">Nothing needs attention</p>
          <p>
            Every schedule ran and delivered on its last run. Change the filter to see all{" "}
            {schedules.length}.
          </p>
        </div>
      ) : (
        <DataGrid
          caption={`Schedules, ${shown.length} shown`}
          columns={columns}
          rows={shown}
          rowKey={(s) => s.id}
          selected={pickedSet}
          onSelectedChange={(next) => setPicked([...next])}
        />
      )}

      {detail ? (
        <Detail
          s={detail}
          onClose={() => onOpen(null)}
          onToggle={() => {
            const pause = detail.state === "active";
            onChange(
              schedules.map((x) =>
                x.id === detail.id
                  ? pause
                    ? {
                        ...x,
                        state: "paused" as const,
                        next: "Paused",
                        last: "Paused by you",
                        lastTone: "warn" as const,
                        pausedWhy: "Paused by you. Nothing is sent until you resume it.",
                      }
                    : {
                        ...x,
                        state: "active" as const,
                        next: "Next run on the schedule",
                        last: "Resumed by you",
                        lastTone: "muted" as const,
                        pausedWhy: undefined,
                      }
                  : x,
              ),
              `${pause ? "Paused" : "Resumed"} “${detail.name}”.`,
            );
          }}
          onDelete={() => {
            onChange(
              schedules.filter((x) => x.id !== detail.id),
              `Deleted “${detail.name}”.`,
            );
            onOpen(null);
          }}
        />
      ) : null}
    </>
  );
}

const RECIPIENT_COLUMNS: Column<SchedRecipient>[] = [
  {
    key: "who",
    header: "Recipient",
    rowHeader: true,
    wrap: true,
    cell: (r) => (
      <>
        {r.who}
        {r.external ? <span className="chip chip--warn">↗ Outside</span> : null}
      </>
    ),
  },
  { key: "format", header: "Format", wrap: true, cell: (r) => `${r.format} · ${r.method}` },
  {
    key: "state",
    header: "State",
    cell: (r) => (
      <span className={`chip chip--${STATE_TONE[r.state]}`}>{STATE_LABEL[r.state]}</span>
    ),
  },
  { key: "detail", header: "Detail", wrap: true, cell: (r) => r.detail },
];

const RUN_COLUMNS: Column<Schedule["runs"][number]>[] = [
  { key: "at", header: "When", rowHeader: true, cell: (r) => r.at },
  { key: "rows", header: "Rows", cell: (r) => r.rows.toLocaleString("en") },
  { key: "outcome", header: "Outcome", wrap: true, cell: (r) => r.outcome },
  { key: "scope", header: "Scope applied", wrap: true, cell: (r) => r.scope },
];

function Detail(props: {
  readonly s: Schedule;
  readonly onClose: () => void;
  readonly onToggle: () => void;
  readonly onDelete: () => void;
}) {
  const { s, onClose, onToggle, onDelete } = props;
  const uid = useId();
  const [confirmDelete, setConfirmDelete] = useState(false);
  return (
    <div className="pt__sheetwrap" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        className="pt__sheet rp__sheet--wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${uid}-h`}
        onKeyDown={(e) => e.key === "Escape" && onClose()}
      >
        <div>
          <h2 id={`${uid}-h`}>{s.name}</h2>
          <p className="pt__sub">
            {s.report} · {s.when} · owner {s.owner}
          </p>
        </div>
        {s.state === "paused" && s.pausedWhy ? (
          <div className="pt__banner" role="status">
            <span>
              <strong>⏸ Paused.</strong> {s.pausedWhy}
            </span>
          </div>
        ) : null}
        <h3 className="rp__h3">Delivery, per recipient (last run)</h3>
        <Table
          caption="Delivery, per recipient (last run)"
          rows={s.recipients}
          rowKey={(r) => r.who}
          columns={RECIPIENT_COLUMNS}
        />
        <h3 className="rp__h3">Runs</h3>
        {s.runs.length === 0 ? (
          <p className="pt__sub">
            Not run yet. The first run is {s.next}. Each run is listed here with the scope it used.
          </p>
        ) : (
          <Table caption="Runs" rows={s.runs} rowKey={(r) => r.at} columns={RUN_COLUMNS} />
        )}
        {s.notifyOnlyIfData ? <p className="pt__sub">“Only send if there is data” is on.</p> : null}
        <div className="pt__actions rp__sticky">
          {s.owner === "You" ? (
            <button type="button" className="btn" onClick={onToggle}>
              {s.state === "active" ? "Pause" : "Resume"}
            </button>
          ) : (
            <span className="pt__sub">Only {s.owner} or a schedule manager can change this.</span>
          )}
          {s.owner === "You" ? (
            confirmDelete ? (
              <>
                <span>Delete this schedule and its run history link?</span>
                <button type="button" className="btn btn--danger" onClick={onDelete}>
                  Delete schedule
                </button>
                <button type="button" className="btn" onClick={() => setConfirmDelete(false)}>
                  Keep
                </button>
              </>
            ) : (
              <button type="button" className="btn" onClick={() => setConfirmDelete(true)}>
                Delete…
              </button>
            )
          ) : null}
          <button type="button" className="btn" onClick={onClose}>
            Close <span className="pt__kbd">Esc</span>
          </button>
        </div>
      </div>
    </div>
  );
}
