import { type ReactNode, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import {
  DataGrid,
  type DataGridColumn,
  type DataGridSort as Sort,
  type Column,
  Table,
} from "../../ds/components";
import "../../ds/components/components.css";
import "../prototype.css";
import "./reports.css";
import {
  AS_OF,
  CATEGORIES,
  CYCLE_FINDING,
  DOMAIN_COUNT,
  GROUPS,
  RUN_TIME,
  REPORTS,
  SCHEDULES,
  TOTAL_CHECKED,
  ZONE,
  buildRows,
  colKey,
  domainNames,
  extraColumns,
  type Cell,
  type DomainName,
  type ReportDef,
  type Row,
  type Schedule,
} from "./fixtures";
import { searchReports, type Hit, HIT_LIMIT } from "./search";
import {
  ALL_PERMS,
  ScheduleSheet,
  type Perms,
  type SheetInitial,
  type Subject,
} from "./ScheduleSheet";
import { Schedules } from "./Schedules";

export type Scenario =
  | "ok"
  | "stale"
  | "notSynced"
  | "emptyScope"
  | "unsupportedScope"
  | "expired"
  | "failed"
  | "loading"
  | "running"
  | "partialDc"
  | "readCap"
  | "cancelled";

export interface Initial {
  readonly view?: "library" | "report" | "schedules";
  readonly report?: string;
  readonly preset?: string;
  readonly group?: string;
  /** The ME name the admin searched for, so the header says "Also known as". */
  readonly alias?: string;
  readonly days?: number;
  readonly filter?: string;
  readonly showSvc?: boolean;
  readonly scenario?: Scenario;
  readonly menu?: "export" | "columns" | "scope";
  readonly sheet?: boolean;
  readonly sheetState?: SheetInitial;
  readonly searchOpen?: boolean;
  readonly query?: string;
  readonly libraryQuery?: string;
  readonly scheduleOpen?: string;
  readonly details?: boolean;
  readonly toast?: "ready";
  readonly forbidden?: boolean;
  readonly unsupportedKind?: string;
}
export interface ExportCaps {
  readonly CSV: number;
  readonly XLSX: number;
}
export interface ReportsProps {
  readonly initial?: Initial;
  readonly perms?: Perms;
  /** Row caps a tenant has lowered per format (spec §8.3). Default is the 1,000,000 hard value. */
  readonly exportCaps?: ExportCaps;
  readonly latencyMs?: number;
}

const BUDGET_FROM_RESULTS = { export: 2, schedule: 6 } as const;

interface ExportRec {
  readonly name: string;
  readonly format: string;
  readonly rows: number;
  readonly at: string;
  readonly expires: string;
}
interface Toast {
  readonly text: ReactNode;
  readonly tone: "info" | "ok";
  readonly action?: { readonly label: string; readonly run: () => void };
  readonly busy?: boolean;
}
interface Params {
  readonly id: string;
  readonly preset: string;
  readonly days: number | null;
  readonly domains: readonly DomainName[];
  readonly showSvc: boolean;
  readonly filter: string;
  readonly sort: Sort | null;
  readonly hidden: readonly string[];
  readonly added: readonly string[];
  readonly group: string | null;
  readonly alias: string | null;
}

const NOUN: Record<ReportDef["kind"], string> = {
  user: "users",
  group: "groups",
  computer: "computers",
  ou: "OUs",
  contact: "contacts",
  member: "members",
};

function sha(seed: string): string {
  let h = 2166136261;
  const parts: string[] = [];
  for (let i = 0; i < 4; i += 1) {
    for (let j = 0; j < seed.length; j += 1) {
      h ^= seed.charCodeAt(j) + i;
      h = Math.imul(h, 16777619);
    }
    parts.push((h >>> 0).toString(16).padStart(8, "0"));
  }
  return parts.join("");
}
const slugName = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

function isTyping(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  return (
    !!el &&
    (el.tagName === "INPUT" ||
      el.tagName === "TEXTAREA" ||
      el.tagName === "SELECT" ||
      el.isContentEditable)
  );
}

export function Reports({
  initial = {},
  perms = ALL_PERMS,
  exportCaps = { CSV: 1_000_000, XLSX: 1_000_000 },
  latencyMs = 220,
}: ReportsProps) {
  const [view, setView] = useState(initial.view ?? "library");
  const [libQuery, setLibQuery] = useState(initial.libraryQuery ?? "");
  const [searchOpen, setSearchOpen] = useState(initial.searchOpen ?? false);
  const [query, setQuery] = useState(initial.query ?? "");
  const [menu, setMenu] = useState<"export" | "columns" | "scope" | null>(initial.menu ?? null);
  const [sheet, setSheet] = useState(initial.sheet ?? false);
  const [toast, setToast] = useState<Toast | null>(null);
  const [ticks, setTicks] = useState<string[]>([]);
  const [stageStart, setStageStart] = useState<number | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const [schedules, setSchedules] = useState<Schedule[]>([...SCHEDULES]);
  const [schedOpen, setSchedOpen] = useState<string | null>(initial.scheduleOpen ?? null);
  const [exportsByRun, setExportsByRun] = useState<Record<string, ExportRec[]>>({});
  const [scenario, setScenario] = useState<Scenario>(initial.scenario ?? "ok");
  const [seq, setSeq] = useState(1);
  const [busy, setBusy] = useState(false);
  const [details, setDetails] = useState(initial.details ?? false);
  const [params, setParams] = useState<Params | null>(() => {
    if (!initial.report) return null;
    const rep = REPORTS.find((r) => r.id === initial.report);
    if (!rep) return null;
    const pr = rep.presets.find((x) => x.id === initial.preset) ?? rep.presets[0];
    return {
      id: rep.id,
      preset: pr?.id ?? "",
      days: initial.days ?? pr?.period ?? null,
      domains: [...domainNames],
      showSvc: initial.showSvc ?? false,
      filter: initial.filter ?? "",
      sort: null,
      hidden: [],
      added: [],
      group: initial.group ?? (rep.requires === "group" ? null : null),
      alias: initial.alias ?? null,
    };
  });

  const tick = useCallback((label: string) => setTicks((t) => [...t, label]), []);
  const report = params ? REPORTS.find((r) => r.id === params.id) : undefined;
  const runId = `R-20261030-${String(1000 + seq)}`;

  useEffect(() => {
    if (initial.report && stageStart === null) setStageStart(0);
    if (initial.toast === "ready" && params && report) {
      setToast({
        tone: "ok",
        text: "Sample toast",
      });
    }
  }, []);

  // A new run for every change of preset, filter, period, scope or columns (FR-11).
  const newRun = (next: Partial<Params>) => {
    setParams((p) => (p ? { ...p, ...next } : p));
    setSeq((s) => s + 1);
    setBusy(true);
    setTimeout(() => setBusy(false), latencyMs);
  };
  const sortOnly = (sort: Sort | null) => setParams((p) => (p ? { ...p, sort } : p));

  const openReport = (h: Hit, fromSearch: boolean) => {
    tick(fromSearch ? "Enter: open report" : "click report");
    setStageStart(ticks.length + 1);
    setSearchOpen(false);
    setView("report");
    setMenu(null);
    setSheet(false);
    setSeq((s) => s + 1);
    setScenario((s) => (s === "expired" || s === "failed" ? "ok" : s));
    setParams({
      id: h.report.id,
      preset: h.preset.id,
      days: h.preset.period,
      domains: [...domainNames],
      showSvc: false,
      filter: "",
      sort: null,
      hidden: [],
      added: [],
      group: h.group?.name ?? null,
      alias: h.alias,
    });
  };

  const restart = () => {
    setView("library");
    setLibQuery("");
    setSearchOpen(false);
    setQuery("");
    setMenu(null);
    setSheet(false);
    setToast(null);
    setTicks([]);
    setStageStart(null);
    setSchedules([...SCHEDULES]);
    setExportsByRun({});
    setScenario("ok");
    setParams(null);
    setResetKey((k) => k + 1);
  };

  // Global keys: "/" search, "E" export, "S" schedule. Never while typing or with a layer open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e.target) || e.ctrlKey || e.metaKey || e.altKey || searchOpen || sheet) return;
      const k = e.key.toLowerCase();
      // E and S follow their buttons: a disabled button means the key does nothing.
      const btn = document.querySelector<HTMLButtonElement>(`button[aria-keyshortcuts="${k}"]`);
      if (btn?.disabled) return;
      if (k === "/" && perms.run) {
        e.preventDefault();
        tick("/ search");
        setQuery("");
        setSearchOpen(true);
      } else if (view === "report" && k === "e" && perms.exportFiles) {
        e.preventDefault();
        tick("E export");
        setMenu("export");
      } else if (view === "report" && k === "s" && perms.schedule) {
        e.preventDefault();
        tick("S schedule");
        setSheet(true);
      } else if (e.key === "Escape") {
        setMenu(null);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [searchOpen, sheet, view, perms, tick]);

  const total = ticks.length;
  const stage = stageStart === null ? 0 : Math.max(0, total - stageStart);

  return (
    <div className="pt rp" key={resetKey}>
      <div className="pt__meter" role="status">
        <span className="pt__tag">Prototype · sample data</span>
        <span>
          Interactions: <strong>{total}</strong>
        </span>
        {view === "report" ? (
          <span>
            From the open report: <strong>{stage}</strong> (budget: export{" "}
            {BUDGET_FROM_RESULTS.export}, schedule {BUDGET_FROM_RESULTS.schedule})
          </span>
        ) : null}
        <span className="pt__sub">{ticks.length ? ticks.join(" → ") : "No interactions yet"}</span>
        <button className="btn" type="button" onClick={restart}>
          Restart
        </button>
      </div>
      <header className="pt__top">
        <button type="button" className="pt__brand" onClick={() => setView("library")}>
          activeDIQ
        </button>
        {perms.run ? (
          <nav aria-label="Main" className="rp__nav">
            <button
              type="button"
              className="pt__tab"
              aria-current="page"
              onClick={() => setView("library")}
            >
              Reports
            </button>
          </nav>
        ) : (
          <nav aria-label="Main" className="rp__nav">
            <span className="pt__sub">Home</span>
          </nav>
        )}
        <button
          type="button"
          className="pt__trigger"
          onClick={() => {
            tick("click search");
            setQuery("");
            setSearchOpen(true);
          }}
        >
          <span>Search reports, users, groups…</span>
          <span className="pt__kbd">/</span>
        </button>
        <span className="pt__who">
          Sample admin · {perms.run ? "Reports" : "Help desk, no reports"}
        </span>
      </header>
      <main className="pt__main rp__main">
        {initial.forbidden || !perms.run ? (
          <Forbidden />
        ) : view === "schedules" ? (
          <>
            <LibTabs
              view="schedules"
              count={schedules.length}
              onView={setView}
              canSchedule={perms.schedule}
            />
            <Schedules
              schedules={schedules}
              open={schedOpen}
              onOpen={setSchedOpen}
              onChange={(next, note) => {
                setSchedules(next);
                setToast({ tone: "ok", text: note });
              }}
            />
          </>
        ) : view === "report" && params && report ? (
          <ReportView
            key={`${report.id}-${params.group ?? ""}`}
            report={report}
            params={params}
            runId={runId}
            scenario={scenario}
            setScenario={setScenario}
            busy={busy}
            perms={perms}
            exportCaps={exportCaps}
            menu={menu}
            setMenu={setMenu}
            details={details}
            setDetails={setDetails}
            exports={exportsByRun[runId] ?? []}
            setExports={(fn) => setExportsByRun((m) => ({ ...m, [runId]: fn(m[runId] ?? []) }))}
            toast={toast}
            setToast={setToast}
            tick={tick}
            newRun={newRun}
            sortOnly={sortOnly}
            onSchedule={() => {
              tick("click Schedule");
              setSheet(true);
            }}
            onBack={() => setView("library")}
            onOpen={openReport}
            forceUnsupported={initial.unsupportedKind}
          />
        ) : (
          <Library
            query={libQuery}
            setQuery={setLibQuery}
            onOpen={openReport}
            onView={setView}
            scheduleCount={schedules.length}
            canSchedule={perms.schedule}
          />
        )}
      </main>
      {searchOpen ? (
        <SearchOverlay
          query={query}
          setQuery={setQuery}
          allowed={perms.run}
          tick={tick}
          onPick={(h) => openReport(h, true)}
          onClose={() => setSearchOpen(false)}
        />
      ) : null}
      {sheet && params && report ? (
        <ScheduleSheet
          subject={subjectFor(report, params)}
          perms={perms}
          initial={initial.sheetState}
          onTick={tick}
          onClose={() => setSheet(false)}
          onSave={(s) => {
            setSchedules((all) => [s, ...all]);
            setSheet(false);
            setToast({
              tone: "ok",
              text: (
                <>
                  <strong>Schedule saved.</strong> {s.when}. First run {s.next}. To{" "}
                  {s.recipients.length} recipient{s.recipients.length === 1 ? "" : "s"}.
                </>
              ),
              action: {
                label: "Undo",
                run: () => {
                  setSchedules((all) => all.filter((x) => x.id !== s.id));
                  setToast({ tone: "info", text: "Schedule removed. Nothing was sent." });
                },
              },
            });
          }}
        />
      ) : null}
      {toast ? (
        <div className={`rp__toast rp__toast--${toast.tone}`} role="status">
          <span>{toast.text}</span>
          {toast.action ? (
            <button type="button" className="btn" onClick={toast.action.run}>
              {toast.action.label}
            </button>
          ) : null}
          <button
            type="button"
            className="rp__x"
            aria-label="Dismiss"
            onClick={() => setToast(null)}
          >
            ×
          </button>
        </div>
      ) : null}
    </div>
  );
}

function subjectFor(report: ReportDef, p: Params): Subject {
  const preset = report.presets.find((x) => x.id === p.preset) ?? report.presets[0];
  const parts = [preset?.name ?? ""];
  if (p.days !== null) parts.push(`${p.days} days`);
  if (p.group) parts.push(p.group);
  if (p.filter) parts.push(`filter “${p.filter}”`);
  const cols = report.columns.length - p.hidden.length + p.added.length;
  return {
    title: report.name,
    filters: parts.join(" · "),
    columns: cols,
    scope: `${p.domains.length} domain${p.domains.length === 1 ? "" : "s"}, every OU in your role (${TOTAL_CHECKED.toLocaleString("en")} objects checked)`,
    rows: 0,
    perDc: !!report.perDc,
  };
}

function LibTabs(props: {
  readonly view: "library" | "schedules";
  readonly count: number;
  readonly onView: (v: "library" | "schedules") => void;
  readonly canSchedule: boolean;
}) {
  return (
    <div className="pt__tabs" role="tablist" aria-label="Reports sections">
      <button
        type="button"
        role="tab"
        aria-selected={props.view === "library"}
        className="pt__tab"
        onClick={() => props.onView("library")}
      >
        Library
      </button>
      {props.canSchedule ? (
        <button
          type="button"
          role="tab"
          aria-selected={props.view === "schedules"}
          className="pt__tab"
          onClick={() => props.onView("schedules")}
        >
          Schedules ({props.count})
        </button>
      ) : null}
    </div>
  );
}

function Forbidden() {
  return (
    <div className="diq-state diq-state--error" role="alert">
      <h1 className="diq-state__title rp__h1">You don’t have access to reports</h1>
      <p>
        Your role does not include running reports (<span className="diq-mono">reports.run</span>
        ). Ask an administrator to add it to your role. Nothing here was changed.
      </p>
    </div>
  );
}

// ---- library ----------------------------------------------------------------------------------

function Library(props: {
  readonly query: string;
  readonly setQuery: (q: string) => void;
  readonly onOpen: (h: Hit, fromSearch: boolean) => void;
  readonly onView: (v: "schedules") => void;
  readonly scheduleCount: number;
  readonly canSchedule: boolean;
}) {
  const { query, setQuery, onOpen, onView, scheduleCount, canSchedule } = props;
  const q = query.trim().toLowerCase();
  const terms = q.split(/\s+/).filter(Boolean);
  const rows = REPORTS.map((r) => {
    const hay = `${r.name} ${r.id} ${r.category} ${r.desc} ${r.dataset}`.toLowerCase();
    const presetHit = r.presets.find(
      (pr) => terms.length > 0 && terms.every((t) => pr.name.toLowerCase().includes(t)),
    );
    const matches = terms.length === 0 || terms.every((t) => hay.includes(t)) || !!presetHit;
    return { r, matches, presetHit };
  }).filter((x) => x.matches);

  return (
    <>
      <LibTabs
        view="library"
        count={scheduleCount}
        onView={(v) => onView(v as "schedules")}
        canSchedule={canSchedule}
      />
      <div className="pt__head">
        <div>
          <h1>Reports</h1>
          <p className="pt__sub">
            16 reports in 6 categories. Each opens with results; no Generate step. ManageEngine
            report names are presets, so “Recently Logged on Users” finds Logon activity.
          </p>
        </div>
        <label className="pt__field rp__libfilter">
          <span className="rp__sr">Filter the library</span>
          <input
            className="rp__input"
            value={query}
            placeholder="Filter by report, ManageEngine name or category"
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
      </div>
      {rows.length === 0 ? (
        <div className="diq-state">
          <p className="diq-state__title">No report matches “{query.trim()}”</p>
          <p>
            Checked report names, categories and the 54 ManageEngine report names. Try fewer
            letters, or clear the filter to see all 16.
          </p>
          <button type="button" className="btn" onClick={() => setQuery("")}>
            Clear filter
          </button>
        </div>
      ) : (
        CATEGORIES.map((cat) => {
          const inCat = rows.filter((x) => x.r.category === cat);
          if (inCat.length === 0) return null;
          return (
            <section key={cat} aria-labelledby={`cat-${slugName(cat)}`}>
              <h2 id={`cat-${slugName(cat)}`}>
                {cat} <span className="pt__sub">{inCat.length}</span>
              </h2>
              <ul className="pt__list">
                {inCat.map(({ r, presetHit }) => {
                  const preset = presetHit ?? r.presets[0];
                  return (
                    <li key={r.id}>
                      <button
                        type="button"
                        className="pt__row rp__librow"
                        onClick={() =>
                          preset &&
                          onOpen(
                            {
                              report: r,
                              preset,
                              alias: presetHit && presetHit.name !== r.name ? presetHit.name : null,
                              label: r.name,
                              sub: "",
                            },
                            false,
                          )
                        }
                      >
                        <span className="rp__libname">
                          <b>{r.name}</b>
                          <span className="pt__sub">{r.desc}</span>
                        </span>
                        <span className="rp__libpresets pt__sub">
                          {presetHit ? (
                            <>
                              Opens preset <b>{presetHit.name}</b>
                            </>
                          ) : (
                            <>
                              Also known as{" "}
                              {r.presets
                                .slice(0, 2)
                                .map((x) => x.name)
                                .join(" · ")}
                              {r.presets.length > 2 ? ` · +${r.presets.length - 2}` : ""}
                            </>
                          )}
                        </span>
                        <span className="diq-mono pt__sub rp__libds">{r.dataset}</span>
                        <span className="chip chip--ok">✓ Synced {AS_OF}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>
          );
        })
      )}
      <p className="pt__sub rp__foot">
        Only reports your role may run are listed. Favourites, compliance packs and the report
        builder arrive in later checkpoints.
      </p>
    </>
  );
}

// ---- search overlay ---------------------------------------------------------------------------

function SearchOverlay(props: {
  readonly query: string;
  readonly setQuery: (q: string) => void;
  readonly allowed: boolean;
  readonly tick: (l: string) => void;
  readonly onPick: (h: Hit) => void;
  readonly onClose: () => void;
}) {
  const { query, setQuery, allowed, tick, onPick, onClose } = props;
  const listId = useId();
  const typed = useRef(false);
  const [active, setActive] = useState(0);
  const trimmed = query.trim();
  const result = useMemo(() => searchReports(trimmed, allowed), [trimmed, allowed]);
  useEffect(() => setActive(0), [trimmed]);

  const key = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
    else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, result.hits.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const h = result.hits[active];
      if (h) onPick(h);
    }
  };
  return (
    <div className="pt__scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        className="pt__overlay"
        role="dialog"
        aria-modal="true"
        aria-label="Search"
        onKeyDown={key}
      >
        <input
          autoFocus
          className="pt__input"
          role="combobox"
          aria-expanded={result.hits.length > 0}
          aria-controls={listId}
          aria-activedescendant={result.hits[active] ? `${listId}-${active}` : undefined}
          aria-label="Search reports"
          placeholder="A report, a ManageEngine report name, or a group"
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(e) => {
            if (!typed.current) {
              typed.current = true;
              tick("type query");
            }
            setQuery(e.target.value);
          }}
        />
        <div aria-live="polite">
          {trimmed === "" ? (
            <p className="pt__msg">
              Try “inactive users”, “password never expires”, “Recently Logged on Users” or “domain
              admins nested”. Searching 16 reports and 54 ManageEngine names.
            </p>
          ) : null}
          {trimmed !== "" && result.total === 0 ? (
            <p className="pt__msg">
              Nothing matches “{trimmed}”. Search checks report names, ManageEngine report names and
              categories; try fewer letters.
            </p>
          ) : null}
        </div>
        {result.hits.length > 0 ? (
          <>
            <div className="rp__group">Reports</div>
            <ul className="pt__list" role="listbox" id={listId} aria-label="Reports">
              {result.hits.map((h, i) => (
                <li
                  key={`${h.report.id}-${h.preset.id}-${h.group?.name ?? ""}`}
                  role="presentation"
                >
                  <div
                    role="option"
                    id={`${listId}-${i}`}
                    aria-selected={i === active}
                    tabIndex={-1}
                    className="pt__row rp__hit"
                    onMouseEnter={() => setActive(i)}
                    onClick={() => onPick(h)}
                  >
                    <span className="pt__name">
                      <b>{h.label}</b>
                      <span className="pt__sub"> {h.sub}</span>
                    </span>
                    {h.alias ? (
                      <span className="chip chip--muted">Also known as {h.alias}</span>
                    ) : null}
                    <span className="chip chip--ok">✓ Synced {AS_OF}</span>
                  </div>
                </li>
              ))}
            </ul>
          </>
        ) : null}
        <div className="pt__hint">
          {result.total > HIT_LIMIT ? `Showing ${HIT_LIMIT} of ${result.total}. ` : ""}↑↓ move ·
          Enter opens with results · Esc closes. Users, groups and computers appear here once the
          console search covers them.
        </div>
      </div>
    </div>
  );
}

// ---- the report ---------------------------------------------------------------------------------

interface ViewProps {
  readonly report: ReportDef;
  readonly params: Params;
  readonly runId: string;
  readonly scenario: Scenario;
  readonly setScenario: (s: Scenario) => void;
  readonly busy: boolean;
  readonly perms: Perms;
  readonly exportCaps: ExportCaps;
  readonly menu: "export" | "columns" | "scope" | null;
  readonly setMenu: (m: "export" | "columns" | "scope" | null) => void;
  readonly details: boolean;
  readonly setDetails: (b: boolean) => void;
  readonly exports: readonly ExportRec[];
  readonly setExports: (fn: (e: ExportRec[]) => ExportRec[]) => void;
  readonly toast: Toast | null;
  readonly setToast: (t: Toast | null) => void;
  readonly tick: (l: string) => void;
  readonly newRun: (p: Partial<Params>) => void;
  readonly sortOnly: (s: Sort | null) => void;
  readonly onSchedule: () => void;
  readonly onBack: () => void;
  readonly onOpen: (h: Hit, fromSearch: boolean) => void;
  readonly forceUnsupported?: string | undefined;
}

function ReportView(props: ViewProps) {
  const {
    report,
    params,
    runId,
    scenario,
    setScenario,
    busy,
    perms,
    exportCaps,
    menu,
    setMenu,
    details,
    setDetails,
    exports,
    setExports,
    setToast,
    tick,
    newRun,
    sortOnly,
    onSchedule,
    onBack,
    onOpen,
    forceUnsupported,
  } = props;
  const preset = report.presets.find((x) => x.id === params.preset) ?? report.presets[0];
  const needsParam = report.requires !== undefined && !params.group;
  const readCap = scenario === "readCap";

  const domains =
    scenario === "notSynced" ? params.domains.filter((d) => d !== "labs.example") : params.domains;
  const base = useMemo(
    () =>
      needsParam || !preset
        ? { rows: [] as Row[], svcHidden: 0 }
        : buildRows({
            report,
            presetId: preset.id,
            days: params.days,
            group: params.group ?? undefined,
          }),
    [report, preset, params.days, params.group, needsParam],
  );

  const columns: DataGridColumn<Row>[] = useMemo(() => {
    const keep = report.columns.filter((c) => !params.hidden.includes(c));
    return [...keep, ...params.added].map((header) => {
      const key = colKey(header);
      return {
        key,
        header,
        sortable: true,
        width: widthFor(key),
        cell: (r: Row) => renderCell(key, r.cells[key], r, scenario),
        title: (r: Row) => String(r.cells[key] ?? ""),
      };
    });
  }, [report, params.hidden, params.added, scenario]);

  const rows = useMemo(() => {
    const f = params.filter.trim().toLowerCase();
    let out = base.rows.filter((r) => params.showSvc || r.svc === undefined);
    if (report.kind !== "member") {
      out = out.filter((r) => {
        const d = r.cells["domain"];
        return d === undefined || domains.includes(d as DomainName);
      });
    }
    if (f)
      out = out.filter((r) =>
        Object.values(r.cells).some((v) => String(v).toLowerCase().includes(f)),
      );
    if (params.sort) {
      const { key, dir } = params.sort;
      const m = dir === "asc" ? 1 : -1;
      out = [...out].sort((a, b) => {
        const x = a.cells[key];
        const y = b.cells[key];
        if (typeof x === "number" && typeof y === "number") return (x - y) * m;
        return String(x ?? "").localeCompare(String(y ?? ""), "en", { numeric: true }) * m;
      });
    }
    return out;
  }, [base.rows, params.showSvc, params.filter, params.sort, domains, report.kind]);

  const checked =
    report.kind === "member" ? rows.length : domains.reduce((n, d) => n + DOMAIN_COUNT[d], 0);
  const asOfLabel = scenario === "stale" ? "06:41" : AS_OF;
  const digest = sha(`${runId}${rows.length}${params.filter}${params.preset}`);
  const noun = NOUN[report.kind];
  const limited = scenario === "emptyScope" || scenario === "unsupportedScope";
  const noRows = rows.length === 0;
  const stateOnly =
    limited ||
    scenario === "failed" ||
    scenario === "expired" ||
    scenario === "loading" ||
    scenario === "running" ||
    readCap ||
    needsParam;
  const canExport = perms.exportFiles && !noRows && !stateOnly;
  const canSchedule = perms.schedule && !limited;
  const exportName = (ext: string) =>
    `${slugName(report.name)}-${slugName(preset?.name ?? "")}-20261030-0943Z.${ext}`;

  const doExport = (fmt: "CSV" | "XLSX") => {
    tick(fmt);
    setMenu(null);
    const ext = fmt.toLowerCase();
    setToast({
      tone: "info",
      busy: true,
      text: `Preparing ${fmt} of ${rows.length.toLocaleString("en")} rows…`,
    });
    const wasExpired = scenario === "expired";
    if (wasExpired) setScenario("ok");
    setTimeout(() => {
      setExports((list) => [
        ...list,
        {
          name: exportName(ext),
          format: fmt,
          rows: rows.length,
          at: `${RUN_TIME} ${ZONE}`,
          expires: "6 Nov 2026",
        },
      ]);
      setToast({
        tone: "ok",
        text: (
          <>
            <strong>{fmt} ready:</strong> <span className="diq-mono">{exportName(ext)}</span> ·{" "}
            {rows.length.toLocaleString("en")} rows · data as of {asOfLabel}.{" "}
            {wasExpired
              ? "This result had expired (kept 7 days), so the report was run again first; the file carries the new time. "
              : ""}
            The browser downloads it now; if it was blocked, use the run details.
          </>
        ),
        action: {
          label: "Run details",
          run: () => {
            setDetails(true);
            setToast(null);
          },
        },
      });
    }, 900);
  };

  const scopeText =
    scenario === "emptyScope" || scenario === "unsupportedScope"
      ? "none"
      : `${domains.length} of 3 domains · every OU in your role`;
  const unsupported = forceUnsupported ?? "group members";

  const clearFilter = () => newRun({ filter: "" });

  return (
    <>
      <div className="rp__crumbs pt__sub">
        <button type="button" className="rp__link" onClick={onBack}>
          Reports
        </button>{" "}
        › {report.category} ›{" "}
        <span className="diq-mono rp__url">
          /reports/{report.id}?preset={preset?.id}
          {params.days !== null ? `&days=${params.days}` : ""}
          {params.group ? `&group=${encodeURIComponent(params.group)}` : ""}
        </span>
      </div>
      <div className="pt__head">
        <div>
          <h1>{report.name}</h1>
          {params.alias ? (
            <p className="pt__sub">
              Also known as <b>{params.alias}</b> in ManageEngine · preset applied
            </p>
          ) : (
            <p className="pt__sub">{report.desc}</p>
          )}
        </div>
        <div className="rp__actwrap">
          <div className="pt__actions" role="toolbar" aria-label="Report actions">
            <div className="rp__pop">
              <button
                type="button"
                className="btn btn--primary"
                aria-haspopup="menu"
                aria-expanded={menu === "export"}
                aria-keyshortcuts="e"
                disabled={!canExport}
                aria-describedby={!perms.exportFiles ? "rp-perm-note" : undefined}
                onClick={() => {
                  tick("click Export");
                  setMenu(menu === "export" ? null : "export");
                }}
              >
                Export <span className="pt__kbd">E</span>
              </button>
              {menu === "export" ? (
                <ExportMenu
                  rows={rows.length}
                  columns={columns.length}
                  caps={exportCaps}
                  ext={report.id === "GRP-02" && params.preset === "detailed"}
                  expired={scenario === "expired"}
                  onPick={doExport}
                  onClose={() => setMenu(null)}
                />
              ) : null}
            </div>
            <button
              type="button"
              className="btn"
              aria-keyshortcuts="s"
              disabled={!canSchedule}
              aria-describedby={!perms.schedule ? "rp-perm-note" : undefined}
              onClick={onSchedule}
            >
              Schedule <span className="pt__kbd">S</span>
            </button>
            <CopyLink />
          </div>
          {!perms.exportFiles || !perms.schedule ? (
            <p id="rp-perm-note" className="pt__sub rp__perm" role="note">
              {!perms.exportFiles && !perms.schedule
                ? "You can run this report but not export or schedule it. Ask an administrator for “export reports” and “schedule reports”."
                : !perms.exportFiles
                  ? "You can run this report but not export it. Ask an administrator for “export reports” (reports.export)."
                  : "You can run and export this report but not schedule it. Ask an administrator for “schedule reports” (reports.schedule)."}
            </p>
          ) : null}
        </div>
      </div>

      <dl className="rp__strip" aria-label="This run">
        <div>
          <dt>Scope</dt>
          <dd>{scopeText}</dd>
        </div>
        <div>
          <dt>Data</dt>
          <dd>
            <Freshness scenario={scenario} perDc={!!report.perDc} />
          </dd>
        </div>
        <div>
          <dt>Rows</dt>
          <dd>
            {stateOnly ? (
              "—"
            ) : (
              <>
                <strong className="diq-mono">{rows.length.toLocaleString("en")}</strong> of{" "}
                {checked.toLocaleString("en")} {noun} checked
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Run</dt>
          <dd>
            <span className="diq-mono">{runId}</span> · {RUN_TIME} {ZONE}
          </dd>
        </div>
        <div>
          <dt>Digest</dt>
          <dd>
            <span className="diq-mono" title={digest}>
              {stateOnly ? "—" : `${digest.slice(0, 10)}…`}
            </span>
          </dd>
        </div>
      </dl>

      <Banners
        scenario={scenario}
        report={report}
        caveat={preset?.caveat}
        onOpenReal={() => {
          const real = REPORTS.find((r) => r.id === "USR-04");
          if (real?.presets[0])
            onOpen(
              { report: real, preset: real.presets[0], alias: null, label: real.name, sub: "" },
              false,
            );
        }}
      />

      {needsParam ? (
        <ParamPicker
          kind={report.requires}
          onPick={(name) =>
            onOpen(
              {
                report,
                preset: preset ?? report.presets[0] ?? { id: "", name: "", base: 0, period: null },
                alias: params.alias,
                label: report.name,
                sub: "",
                group: GROUPS.find((g) => g.name === name),
              },
              false,
            )
          }
        />
      ) : (
        <>
          <Controls
            report={report}
            params={params}
            columnsOpen={menu === "columns"}
            scopeOpen={menu === "scope"}
            setMenu={setMenu}
            newRun={newRun}
            disabled={limited}
            scenario={scenario}
            svcHidden={base.svcHidden}
          />
          <Findings report={report} params={params} />
          <RunBody
            scenario={scenario}
            setScenario={setScenario}
            unsupported={unsupported}
            noRows={noRows}
            filter={params.filter}
            checked={checked}
            domainsN={domains.length}
            noun={noun}
            asOf={asOfLabel}
            onClearFilter={clearFilter}
            runId={runId}
            setSeq={() => newRun({})}
            tick={tick}
            grid={
              <DataGrid
                caption={`${report.name}: ${preset?.name ?? ""}, ${rows.length} rows`}
                columns={columns}
                rows={rows}
                rowKey={(r) => r.key}
                sort={params.sort}
                busy={busy}
                resizable
                onSort={(k) =>
                  sortOnly(
                    params.sort?.key === k
                      ? params.sort.dir === "asc"
                        ? { key: k, dir: "desc" }
                        : null
                      : { key: k, dir: "asc" },
                  )
                }
              />
            }
            rowsCount={rows.length}
            perDc={!!report.perDc}
          />
        </>
      )}

      {!stateOnly ? (
        <RunDetails
          open={details}
          setOpen={setDetails}
          runId={runId}
          digest={digest}
          report={report}
          exports={exports}
          onDelete={(name) => {
            setExports((l) => l.filter((x) => x.name !== name));
            setToast({ tone: "ok", text: `Deleted ${name}. The link no longer works.` });
          }}
        />
      ) : null}
    </>
  );
}

function CopyLink() {
  const [msg, setMsg] = useState("");
  return (
    <>
      <button
        type="button"
        className="btn"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(window.location.href);
            setMsg(
              "Link copied. It shares the view, not the data: others see only their own scope.",
            );
          } catch {
            setMsg("Copy blocked by the browser; copy the address from the bar.");
          }
          setTimeout(() => setMsg(""), 4000);
        }}
      >
        Copy link
      </button>
      <span role="status" className="pt__sub rp__copymsg">
        {msg}
      </span>
    </>
  );
}

function Freshness({ scenario, perDc }: { readonly scenario: Scenario; readonly perDc: boolean }) {
  if (scenario === "stale")
    return <span className="chip chip--warn">⚠ Stale: last sync 3 h ago (emea.corp.example)</span>;
  if (scenario === "notSynced")
    return <span className="chip chip--muted">◷ Not synced yet: labs.example (skipped)</span>;
  if (perDc && scenario === "partialDc")
    return <span className="chip chip--warn">● Read from 5 of 6 DCs at 09:43</span>;
  if (perDc && scenario === "ok")
    return <span className="chip chip--ok">● Read from 6 of 6 DCs at 09:43</span>;
  if (scenario === "emptyScope" || scenario === "unsupportedScope")
    return <span className="chip chip--muted">○ No data in scope</span>;
  if (scenario === "expired")
    return <span className="chip chip--muted">○ Expired: was synced 09:41 on 23 Oct</span>;
  return <span className="chip chip--ok">✓ Synced {AS_OF}</span>;
}

function Banners(props: {
  readonly scenario: Scenario;
  readonly report: ReportDef;
  readonly caveat?: string | undefined;
  readonly onOpenReal: () => void;
}) {
  const { scenario, report, caveat, onOpenReal } = props;
  return (
    <>
      {scenario === "stale" ? (
        <div className="pt__banner rp__warn" role="status">
          <span>
            <strong>⚠ Stale data.</strong> The last successful sync of <b>emea.corp.example</b> was
            3 hours ago (06:41) because that connection is waiting for a full resync. This report
            ran on what activeDIQ last saw. Exports and scheduled deliveries carry this warning.
          </span>
        </div>
      ) : null}
      {scenario === "notSynced" ? (
        <div className="pt__banner rp__warn" role="status">
          <span>
            <strong>◷ Not synced yet: labs.example.</strong> That domain has not finished its first
            sync, so it is skipped. The rows below cover the other 2 of 3 domains.
          </span>
        </div>
      ) : null}
      {scenario === "partialDc" ? (
        <div className="pt__banner rp__warn" role="status">
          <span>
            <strong>● Read from 5 of 6 domain controllers.</strong> dc-ams-03.emea.corp.example did
            not answer (LDAP timeout after 30 s). Dates are the latest logon found, “at least”; “Not
            confirmed” means none of the 5 DCs that answered recorded a logon. It does not mean the
            account never logged on.
          </span>
        </div>
      ) : null}
      {caveat ? (
        <div className="pt__banner rp__note" role="note">
          <span>
            <strong>Read this first.</strong> {caveat}
          </span>
          {report.id === "USR-03" ? (
            <button type="button" className="btn" onClick={onOpenReal}>
              Open Real last logon
            </button>
          ) : null}
        </div>
      ) : null}
    </>
  );
}

function ExportMenu(props: {
  readonly rows: number;
  readonly columns: number;
  readonly caps: ExportCaps;
  readonly ext: boolean;
  readonly expired: boolean;
  readonly onPick: (f: "CSV" | "XLSX") => void;
  readonly onClose: () => void;
}) {
  const { rows, columns, caps, ext, expired, onPick, onClose } = props;
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.querySelector<HTMLElement>("[role=menuitem]:not([aria-disabled])")?.focus();
    const away = (e: MouseEvent) => {
      if (ref.current && !ref.current.parentElement?.contains(e.target as Node)) onClose();
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [onClose]);
  const items = [
    {
      f: "XLSX" as const,
      key: "X",
      note: ext
        ? "evidence pack: About sheet, Via path, digest"
        : "About sheet with scope, filters, freshness and digest",
    },
    { f: "CSV" as const, key: "C", note: "table only, opens in any spreadsheet" },
  ];
  const fmt = (n: number) => n.toLocaleString("en");
  const overOf = (f: "CSV" | "XLSX") => rows > caps[f];
  const pick = (f: "CSV" | "XLSX") => {
    if (overOf(f)) return;
    onPick(f);
  };
  const overFormats = items.filter((it) => overOf(it.f));
  const okFormats = items.filter((it) => !overOf(it.f));
  return (
    <div
      ref={ref}
      className="rp__menu"
      onKeyDown={(e) => {
        const k = e.key.toLowerCase();
        if (e.key === "Escape") {
          e.stopPropagation();
          onClose();
        } else if (k === "x") pick("XLSX");
        else if (k === "c") pick("CSV");
        else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const els = Array.from(
            ref.current?.querySelectorAll<HTMLElement>("[role=menuitem]") ?? [],
          );
          const i = els.indexOf(document.activeElement as HTMLElement);
          els[(i + (e.key === "ArrowDown" ? 1 : els.length - 1)) % els.length]?.focus();
        }
      }}
    >
      <div className="rp__menuhead pt__sub">
        {rows.toLocaleString("en")} rows · {columns} columns as shown · the full result, not just
        this page
      </div>
      {expired ? (
        <div className="rp__menunote pt__sub">
          This result has expired. Exporting runs the report again first and says so.
        </div>
      ) : null}
      <div role="menu" aria-label="Export format">
        {items.map((it) => (
          <button
            key={it.f}
            type="button"
            role="menuitem"
            className="rp__item"
            aria-disabled={overOf(it.f) ? true : undefined}
            onClick={() => pick(it.f)}
          >
            <span>
              <b>{it.f}</b>
              <span className="pt__sub">
                {" "}
                {overOf(it.f) ? `limit ${fmt(caps[it.f])} rows` : it.note}
              </span>
            </span>
            <span className="pt__kbd">{it.key}</span>
          </button>
        ))}
      </div>
      {overFormats.length > 0 ? (
        <div className="rp__menunote rp__err" role="alert">
          This export has {fmt(rows)} rows.{" "}
          {overFormats.length === items.length
            ? caps.CSV === caps.XLSX
              ? `Your organisation limits CSV and XLSX to ${fmt(caps.CSV)}. `
              : `Your organisation limits CSV to ${fmt(caps.CSV)} and XLSX to ${fmt(caps.XLSX)}. `
            : `Your organisation limits ${overFormats[0]?.f} to ${fmt(caps[overFormats[0]?.f ?? "CSV"])}. `}
          {overFormats.length === items.length
            ? "No file was created. Narrow the filters (period, domain or column filter) and export again."
            : `No file was created. ${okFormats[0]?.f} allows ${fmt(caps[okFormats[0]?.f ?? "CSV"])} rows: choose ${okFormats[0]?.f} (${okFormats[0]?.key}), or narrow the filters (period, domain or column filter).`}
        </div>
      ) : null}
    </div>
  );
}

function Controls(props: {
  readonly report: ReportDef;
  readonly params: Params;
  readonly columnsOpen: boolean;
  readonly scopeOpen: boolean;
  readonly setMenu: (m: "export" | "columns" | "scope" | null) => void;
  readonly newRun: (p: Partial<Params>) => void;
  readonly disabled: boolean;
  readonly scenario: Scenario;
  readonly svcHidden: number;
}) {
  const { report, params, columnsOpen, scopeOpen, setMenu, newRun, disabled, svcHidden } = props;
  const periods = (report.minPeriod ? [30, 90, 180, 365] : [7, 30, 90, 180, 365]).filter(
    (d) => d >= (report.minPeriod ?? 0),
  );
  const extra = extraColumns(report);
  return (
    <div className="rp__controls">
      <div className="rp__chips" role="radiogroup" aria-label="Preset">
        {report.presets.map((p) => (
          <button
            key={p.id}
            type="button"
            role="radio"
            aria-checked={params.preset === p.id}
            className={`rp__seg${params.preset === p.id ? " rp__seg--on" : ""}`}
            disabled={disabled}
            onClick={() =>
              params.preset !== p.id &&
              newRun({ preset: p.id, days: p.period, filter: "", alias: null })
            }
          >
            {p.name}
          </button>
        ))}
      </div>
      <div className="rp__row">
        {params.days !== null ? (
          <label className="pt__field">
            <span>Period</span>
            <select
              className="rp__select"
              value={params.days}
              disabled={disabled}
              onChange={(e) => newRun({ days: Number(e.target.value) })}
            >
              {periods.map((d) => (
                <option key={d} value={d}>
                  {report.id === "USR-03" || report.id === "CMP-02"
                    ? `Inactive ${d} days`
                    : `Last ${d} days`}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <div className="rp__pop" hidden={report.kind === "member"}>
          <button
            type="button"
            className="btn"
            aria-haspopup="true"
            aria-expanded={scopeOpen}
            disabled={disabled}
            onClick={() => setMenu(scopeOpen ? null : "scope")}
          >
            Domains: {params.domains.length} of 3
          </button>
          {scopeOpen ? (
            <div className="rp__menu rp__menu--form" role="group" aria-label="Domains">
              {domainNames.map((d) => (
                <label key={d} className="pt__check">
                  <input
                    type="checkbox"
                    checked={params.domains.includes(d)}
                    onChange={(e) => {
                      const next = e.target.checked
                        ? [...params.domains, d]
                        : params.domains.filter((x) => x !== d);
                      if (next.length === 0) return;
                      newRun({ domains: next });
                    }}
                  />
                  <span>
                    {d} <span className="pt__sub">{DOMAIN_COUNT[d].toLocaleString("en")}</span>
                  </span>
                </label>
              ))}
              <p className="pt__sub">At least one domain stays selected.</p>
            </div>
          ) : null}
        </div>
        <label className="pt__field rp__grow">
          <span>Filter rows</span>
          <input
            className="rp__input"
            value={params.filter}
            disabled={disabled}
            placeholder="Name, logon name, OU…"
            onChange={(e) => newRun({ filter: e.target.value })}
          />
        </label>
        <div className="rp__pop">
          <button
            type="button"
            className="btn"
            aria-haspopup="true"
            aria-expanded={columnsOpen}
            disabled={disabled}
            onClick={() => setMenu(columnsOpen ? null : "columns")}
          >
            Columns
          </button>
          {columnsOpen ? (
            <div
              className="rp__menu rp__menu--form rp__menu--right"
              role="group"
              aria-label="Columns"
            >
              {report.columns.map((c) => (
                <label key={c} className="pt__check">
                  <input
                    type="checkbox"
                    checked={!params.hidden.includes(c)}
                    disabled={c === report.columns[0]}
                    onChange={(e) =>
                      newRun({
                        hidden: e.target.checked
                          ? params.hidden.filter((x) => x !== c)
                          : [...params.hidden, c],
                      })
                    }
                  />
                  <span>{c}</span>
                </label>
              ))}
              {extra.length > 0 ? <div className="rp__menuhead pt__sub">More columns</div> : null}
              {extra.map((c) => (
                <label key={c} className="pt__check">
                  <input
                    type="checkbox"
                    checked={params.added.includes(c)}
                    onChange={(e) =>
                      newRun({
                        added: e.target.checked
                          ? [...params.added, c]
                          : params.added.filter((x) => x !== c),
                      })
                    }
                  />
                  <span>{c}</span>
                </label>
              ))}
            </div>
          ) : null}
        </div>
        {report.svcHidden && svcHidden > 0 ? (
          <label className="pt__check rp__svc">
            <input
              type="checkbox"
              checked={params.showSvc}
              onChange={(e) => newRun({ showSvc: e.target.checked })}
            />
            <span>
              {params.showSvc
                ? `Showing ${svcHidden} probable service accounts, each with its reason`
                : `${svcHidden} probable service accounts hidden`}
            </span>
          </label>
        ) : null}
      </div>
    </div>
  );
}

function Findings({ report, params }: { readonly report: ReportDef; readonly params: Params }) {
  if (report.id !== "GRP-02" || params.group !== "Domain Admins" || params.preset === "direct")
    return null;
  return (
    <div className="pt__box rp__findings" role="note">
      <strong>Domain Admins:</strong> 4 direct · 14 effective · 3 levels deep.
      <ul>
        <li>
          <b>⚠ 1 cycle found:</b> <span className="diq-mono">{CYCLE_FINDING}</span>. Members are
          counted once.
        </li>
        <li>
          <b>↗ 1 external principal</b> from partner.example is unresolved (shown by SID).
        </li>
        <li>
          <b>⊘ 2 disabled members</b> still count and are flagged in Status.
        </li>
        <li>Covered domains: corp.example, emea.corp.example.</li>
      </ul>
    </div>
  );
}

function ParamPicker({
  kind,
  onPick,
}: {
  readonly kind: "group" | "user" | undefined;
  readonly onPick: (name: string) => void;
}) {
  const [q, setQ] = useState("");
  const names =
    kind === "group" ? GROUPS.map((g) => g.name) : ["Priya Raman", "Prakash Ramanathan"];
  const shown = names.filter((n) => n.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <div className="diq-state rp__picker">
      <p className="diq-state__title">
        {kind === "group" ? "Pick a group to see its members" : "Pick a user to see their groups"}
      </p>
      <p>
        This report needs {kind === "group" ? "one or more groups" : "one or more users"}; there is
        nothing to show until you choose. Tip: search “domain admins nested” from anywhere to skip
        this step.
      </p>
      <label className="pt__field">
        <span>{kind === "group" ? "Group" : "User"}</span>
        <input
          autoFocus
          className="rp__input"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={kind === "group" ? "Start typing a group name" : "Start typing a name"}
        />
      </label>
      {shown.length === 0 ? (
        <p className="pt__sub">
          No {kind} matches “{q}”.
        </p>
      ) : (
        <ul className="pt__list">
          {shown.map((n) => (
            <li key={n}>
              <button type="button" className="pt__row" onClick={() => onPick(n)}>
                <span className="pt__name">{n}</span>
                {kind === "group" ? (
                  <span className="pt__sub">
                    {GROUPS.find((g) => g.name === n)?.direct.toLocaleString("en")} direct ·{" "}
                    {GROUPS.find((g) => g.name === n)?.effective.toLocaleString("en")} effective
                  </span>
                ) : null}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function RunBody(props: {
  readonly scenario: Scenario;
  readonly setScenario: (s: Scenario) => void;
  readonly unsupported: string;
  readonly noRows: boolean;
  readonly filter: string;
  readonly checked: number;
  readonly domainsN: number;
  readonly noun: string;
  readonly asOf: string;
  readonly onClearFilter: () => void;
  readonly runId: string;
  readonly setSeq: () => void;
  readonly tick: (l: string) => void;
  readonly grid: ReactNode;
  readonly rowsCount: number;
  readonly perDc: boolean;
}) {
  const {
    scenario,
    setScenario,
    unsupported,
    noRows,
    filter,
    checked,
    domainsN,
    noun,
    asOf,
    onClearFilter,
    runId,
    setSeq,
    grid,
    rowsCount,
    perDc,
  } = props;
  const [progress, setProgress] = useState(scenario === "running" ? 33 : 0);
  useEffect(() => {
    if (scenario !== "running") return;
    const id = setInterval(() => {
      setProgress((p) => {
        if (p >= 100) {
          clearInterval(id);
          setScenario("partialDc");
          return 100;
        }
        return p + 9;
      });
    }, 700);
    return () => clearInterval(id);
  }, [scenario, setScenario]);

  if (scenario === "emptyScope")
    return (
      <div className="diq-state" role="status">
        <p className="diq-state__title">Your role covers no directory objects</p>
        <p>
          Ask an administrator to grant a scope. There are zero rows because nothing is in your
          scope; this is not an error and nothing is broken.
        </p>
        <CopyRequest text="Please grant my role a directory scope (a domain or an OU) so I can run reports. Today it covers no objects." />
      </div>
    );
  if (scenario === "unsupportedScope")
    return (
      <div className="diq-state" role="status">
        <p className="diq-state__title">Reports can’t use your role’s scope yet</p>
        <p>
          Your role is scoped by <b>{unsupported}</b>, which reports don’t support at this stage.
          Reports return nothing rather than guess, so there are zero rows. Ask an administrator to
          scope your role by domain or OU.
        </p>
        <CopyRequest
          text={`Please give my role a domain or OU scope for reports. It is scoped by ${unsupported}, which reports can't use yet.`}
        />
      </div>
    );
  if (scenario === "expired")
    return (
      <div className="diq-state" role="status">
        <p className="diq-state__title">This result has expired</p>
        <p>
          Results are kept 7 days; this one was run on 23 Oct at 09:43. It is not shown as current.
          Run it again with the same settings to see today’s data. Exporting does this for you
          first.
        </p>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => {
            setScenario("ok");
            setSeq();
          }}
        >
          Run again with the same settings
        </button>
      </div>
    );
  if (scenario === "failed")
    return (
      <div className="diq-state diq-state--error" role="alert">
        <p className="diq-state__title">This run failed: the query timed out</p>
        <p>
          The database did not answer within 30 s. Nothing was changed and no file or e-mail was
          sent. Run <span className="diq-mono">{runId}</span> is kept with this reason.
        </p>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => {
            setScenario("loading");
            setTimeout(() => setScenario("ok"), 700);
          }}
        >
          Retry
        </button>
      </div>
    );
  if (scenario === "loading")
    return (
      <div className="rp__skels" role="status" aria-label="Running the report">
        {Array.from({ length: 9 }, (_, i) => (
          <div key={i} className="pt__skel" />
        ))}
        <p className="pt__sub">Running… the first page appears as soon as it is ready.</p>
      </div>
    );
  if (scenario === "readCap")
    return (
      <div className="diq-state" role="alert">
        <p className="diq-state__title">This run is too large to start</p>
        <p>
          It would read 52,000 accounts from 6 domain controllers (312,000 reads). The limit is
          250,000 per run, to protect the DCs. Nothing was read. Narrow the domains, the period or
          the filter, then run it again.
        </p>
      </div>
    );
  if (scenario === "running")
    return (
      <div className="diq-state" role="status">
        <p className="diq-state__title">Reading domain controllers…</p>
        <p>
          {Math.min(progress, 100)}% · {Math.round((progress / 100) * 12431).toLocaleString("en")}{" "}
          of 12,431 accounts read across 6 DCs. This runs in the background; you can leave the page
          and it keeps going.
        </p>
        <progress max={100} value={Math.min(progress, 100)} aria-label="Run progress" />
        <button type="button" className="btn" onClick={() => setScenario("cancelled")}>
          Cancel run
        </button>
      </div>
    );
  if (scenario === "cancelled")
    return (
      <div className="diq-state" role="status">
        <p className="diq-state__title">Run cancelled</p>
        <p>Nothing was changed. No partial result is kept as current.</p>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => {
            setScenario("running");
            setProgress(0);
          }}
        >
          Run again
        </button>
      </div>
    );
  if (noRows)
    return (
      <div className="diq-state" role="status">
        <p className="diq-state__title">No {noun} match</p>
        <p>
          {checked.toLocaleString("en")} {noun} were checked in {domainsN} domain
          {domainsN === 1 ? "" : "s"} as of {asOf}.
          {filter ? ` Your row filter “${filter}” matched none of them.` : ""}
        </p>
        {filter ? (
          <button type="button" className="btn" onClick={onClearFilter}>
            Remove filter “{filter}”
          </button>
        ) : null}
      </div>
    );
  return (
    <>
      {grid}
      <p className="pt__sub rp__foot" role="status">
        {rowsCount.toLocaleString("en")} rows · sorted and filtered on the server; scrolling loads
        more · no row selection in this checkpoint{perDc ? "" : ""}
      </p>
    </>
  );
}

function CopyRequest({ text }: { readonly text: string }) {
  const [msg, setMsg] = useState("");
  return (
    <>
      <button
        type="button"
        className="btn"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text);
            setMsg("Copied. Paste it into a message to your administrator.");
          } catch {
            setMsg(text);
          }
        }}
      >
        Copy a request for your administrator
      </button>
      <p role="status" className="pt__sub">
        {msg}
      </p>
    </>
  );
}

function RunDetails(props: {
  readonly open: boolean;
  readonly setOpen: (b: boolean) => void;
  readonly runId: string;
  readonly digest: string;
  readonly report: ReportDef;
  readonly exports: readonly ExportRec[];
  readonly onDelete: (name: string) => void;
}) {
  const { open, setOpen, runId, digest, report, exports, onDelete } = props;
  return (
    <section className="rp__details" aria-label="Run details">
      <button
        type="button"
        className="rp__link"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {open ? "▾" : "▸"} Run details and files ({exports.length})
      </button>
      {open ? (
        <div>
          <dl>
            <dt>Run</dt>
            <dd className="diq-mono">{runId}</dd>
            <dt>Definition</dt>
            <dd>
              {report.id} {report.name}, version 1 (immutable)
            </dd>
            <dt>Run by</dt>
            <dd>You, with your access now</dd>
            <dt>Data as of</dt>
            <dd>
              {AS_OF} {ZONE} (oldest covered sync)
            </dd>
            <dt>Digest (SHA-256, sample)</dt>
            <dd className="diq-mono">{digest}</dd>
          </dl>
          <h2 className="rp__h3">Files from this run</h2>
          {exports.length === 0 ? (
            <p className="pt__sub">
              None yet. Press <span className="pt__kbd">E</span> to export this exact result.
            </p>
          ) : (
            <Table
              caption="Files from this run"
              rows={exports}
              rowKey={(x) => x.name}
              columns={fileColumns(onDelete)}
            />
          )}
        </div>
      ) : null}
    </section>
  );
}

/** Initial column widths in characters (ch), by column kind. Users can resize. */
function widthFor(key: string): number {
  if (key === "name" || key === "member" || key === "user" || key === "via") return 30;
  if (key === "group") return 18;
  if (key.includes("ou-path") || key === "path") return 24;
  if (key === "domain" || key === "upn" || key === "dns-name" || key === "e-mail") return 20;
  if (key.startsWith("days") || key === "users" || key === "computers" || key === "groups")
    return 13;
  if (key === "status" || key === "membership-kind" || key === "member-type") return 18;
  if (key === "probable-service-account") return 26;
  return 19;
}

const fileColumns = (onDelete: (name: string) => void): Column<ExportRec>[] => [
  {
    key: "file",
    header: "File",
    rowHeader: true,
    mono: true,
    title: (x) => x.name,
    cell: (x) => x.name,
  },
  { key: "rows", header: "Rows", cell: (x) => x.rows.toLocaleString("en") },
  { key: "at", header: "Made", cell: (x) => x.at },
  { key: "expires", header: "Expires", cell: (x) => x.expires },
  {
    key: "delete",
    header: "Actions",
    cell: (x) => (
      <button type="button" className="btn" onClick={() => onDelete(x.name)}>
        Delete file
      </button>
    ),
  },
];

function renderCell(col: string, v: Cell | undefined, row: Row, scenario: Scenario): ReactNode {
  const text = v === undefined ? "" : String(v);
  if (col === "status") {
    if (text === "Enabled") return <span className="chip chip--ok">● Enabled</span>;
    if (text === "Disabled") return <span className="chip chip--muted">⊘ Disabled</span>;
    if (text === "Unknown") return <span className="chip chip--warn">? Unknown</span>;
    return text;
  }
  if (col === "member-type" && text.startsWith("External"))
    return <span className="chip chip--warn">↗ {text}</span>;
  if (col === "membership-kind")
    return (
      <span className="chip chip--muted">{text === "Direct" ? "● Direct" : "◌ Effective"}</span>
    );
  if (col === "probable-service-account")
    return row.svc ? <span className="chip chip--warn">Probable: {row.svc}</span> : "No";
  if (col === "real-last-logon" && scenario === "partialDc")
    return Number(row.key.split("|")[2]) % 5 === 0 ? (
      <span className="chip chip--warn">Not confirmed</span>
    ) : (
      <span>at least {text}</span>
    );
  if (col === "dc-coverage")
    return scenario === "partialDc" ? (
      <span className="chip chip--warn">5 of 6</span>
    ) : (
      <span className="chip chip--ok">6 of 6</span>
    );
  if (
    col === "ou-path" ||
    col === "path" ||
    col === "via" ||
    col === "logon-name" ||
    col === "upn" ||
    col === "dns-name"
  )
    return (
      <span className={col === "ou-path" || col === "path" || col === "via" ? "" : "diq-mono"}>
        {text}
      </span>
    );
  if (col === "name" || col === "member" || col === "group" || col === "user") return text;
  if (typeof v === "number") return <span className="diq-mono">{v.toLocaleString("en")}</span>;
  return text;
}
