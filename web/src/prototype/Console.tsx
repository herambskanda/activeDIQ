import { type FormEvent, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import {
  DOMAIN_USER_COUNT,
  NAMED,
  SAMPLE_CODE,
  SAMPLE_TIME,
  type SampleUser,
  buildDirectory,
  phonetic,
  samplePassphrase,
} from "./fixtures";
import { RESULT_LIMIT, searchUsers } from "./search";
import "./prototype.css";

export type Intent = "lookup" | "reset";
export interface Initial {
  readonly searchOpen?: boolean;
  readonly query?: string;
  readonly user?: string;
  readonly sheet?: boolean;
  readonly intent?: Intent;
}
export interface ConsoleProps {
  readonly initial?: Initial;
  /** Simulated search latency, ms. Sample only. */
  readonly latencyMs?: number;
  /** The first search fails once, to show the error state; Retry succeeds. */
  readonly failFirstSearch?: boolean;
}

const T01_BUDGET = 7;
const STAGE_BUDGET = 3;

function useDirectory() {
  return useMemo(() => buildDirectory(), []);
}

function Chips({ u, fixed }: { readonly u: SampleUser; readonly fixed: string | null }) {
  const locked = fixed === null ? u.lockedSince : null;
  return (
    <>
      {locked ? <span className="chip chip--crit">⚠ Locked {locked}</span> : null}
      {u.pwdExpired ? <span className="chip chip--warn">◷ Password expired</span> : null}
      {fixed !== null ? <span className="chip chip--ok">✓ Unlocked {fixed}</span> : null}
      {u.factor === "none" ? <span className="chip chip--muted">○ No code factor</span> : null}
      {u.access === "privileged" ? (
        <span className="chip chip--warn">★ Protected account</span>
      ) : null}
    </>
  );
}

export function Console({ initial = {}, latencyMs = 120, failFirstSearch = false }: ConsoleProps) {
  const directory = useDirectory();
  const [searchOpen, setSearchOpen] = useState(initial.searchOpen ?? false);
  const [query, setQuery] = useState(initial.query ?? "");
  const [intent, setIntent] = useState<Intent | null>(initial.intent ?? null);
  const [userSam, setUserSam] = useState<string | null>(initial.user ?? null);
  const [sheet, setSheet] = useState(initial.sheet ?? false);
  const [unlockedAt, setUnlockedAt] = useState<Record<string, string>>({});
  const [ticks, setTicks] = useState<string[]>([]);
  const [stageStart, setStageStart] = useState<number | null>(initial.user ? 0 : null);
  const [resetKey, setResetKey] = useState(0);

  const tick = useCallback((label: string) => setTicks((t) => [...t, label]), []);
  const user = userSam === null ? undefined : directory.find((u) => u.sam === userSam);

  const restart = () => {
    setSearchOpen(false);
    setQuery("");
    setIntent(null);
    setUserSam(null);
    setSheet(false);
    setUnlockedAt({});
    setTicks([]);
    setStageStart(null);
    setResetKey((k) => k + 1);
  };

  const openSearch = useCallback(
    (why: string, i: Intent | null = null) => {
      tick(why);
      setIntent(i);
      setQuery("");
      setSearchOpen(true);
    },
    [tick],
  );
  const openUser = (u: SampleUser, withSheet: boolean) => {
    tick(withSheet ? "Enter: open Priya + reset sheet" : "Enter: open user");
    setSearchOpen(false);
    setUserSam(u.sam);
    setStageStart(ticks.length + 1);
    setSheet(withSheet);
    if (withSheet) setStageStart(ticks.length + 1);
  };
  const openSheet = useCallback(
    (why: string) => {
      tick(why);
      setSheet(true);
    },
    [tick],
  );

  // Global keys: "/" opens search, "R" opens the reset sheet on a user page. Never while typing.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      const typing =
        t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
      if (typing || e.ctrlKey || e.metaKey || e.altKey || searchOpen || sheet) return;
      if (e.key === "/") {
        e.preventDefault();
        openSearch("/ search");
      } else if ((e.key === "r" || e.key === "R") && user) {
        e.preventDefault();
        openSheet("R reset & unlock");
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [searchOpen, sheet, user, openSearch, openSheet]);

  const total = ticks.length;
  const stage = stageStart === null ? 0 : Math.max(0, total - stageStart);

  return (
    <div className="pt" key={resetKey}>
      <div className="pt__meter" role="status">
        <span className="pt__tag">Prototype · sample data</span>
        <span>
          Interactions this task: <strong>{total}</strong> of {T01_BUDGET} (T01 budget, top-20
          benchmark)
        </span>
        {user ? (
          <span>
            From the user page: <strong>{stage}</strong> of {STAGE_BUDGET}
          </span>
        ) : null}
        <span className="pt__sub">{ticks.length ? ticks.join(" → ") : "No interactions yet"}</span>
        <button className="btn" type="button" onClick={restart}>
          Restart
        </button>
      </div>
      <header className="pt__top">
        <button
          type="button"
          className="pt__brand"
          onClick={() => {
            setUserSam(null);
            setSheet(false);
            setStageStart(null);
          }}
        >
          activeDIQ
        </button>
        <button type="button" className="pt__trigger" onClick={() => openSearch("click search")}>
          <span>Search users by name, account, UPN or e-mail</span>
          <span className="pt__kbd">/</span>
        </button>
        <span className="pt__who">Sample technician · Help desk</span>
      </header>
      <main className="pt__main">
        {user ? (
          <ObjectView
            key={user.sam}
            user={user}
            unlockedAt={unlockedAt[user.sam] ?? null}
            onReset={() => openSheet("click Reset & unlock")}
          />
        ) : (
          <Home
            onTask={(i) =>
              openSearch(i === "reset" ? "click tile: reset" : "click tile: look up", i)
            }
            onRecent={(u) => {
              tick("click recent");
              setUserSam(u.sam);
              setStageStart(ticks.length + 1);
            }}
          />
        )}
      </main>
      {searchOpen ? (
        <SearchOverlay
          directory={directory}
          query={query}
          setQuery={setQuery}
          intent={intent}
          latencyMs={latencyMs}
          failFirst={failFirstSearch}
          onFirstType={() => tick("type query")}
          onPick={(u) => openUser(u, intent === "reset" && u.access !== "denied" ? true : false)}
          onClose={() => setSearchOpen(false)}
        />
      ) : null}
      {sheet && user ? (
        <ResetSheet
          user={user}
          alreadyUnlocked={unlockedAt[user.sam] !== undefined}
          onCodeTyped={() => tick("type code")}
          onConfirm={() => tick("Enter: confirm")}
          onDone={(unlocked) => {
            if (unlocked) setUnlockedAt((m) => ({ ...m, [user.sam]: SAMPLE_TIME.slice(11) }));
            setSheet(false);
          }}
          onClose={() => setSheet(false)}
        />
      ) : null}
    </div>
  );
}

function Home({
  onTask,
  onRecent,
}: {
  readonly onTask: (i: Intent) => void;
  readonly onRecent: (u: SampleUser) => void;
}) {
  return (
    <>
      <h1>What do you need to do?</h1>
      <p className="pt__sub">
        Press <span className="pt__kbd">/</span> from anywhere to search. Tiles pre-select what
        Enter does.
      </p>
      <div className="pt__tiles">
        <button type="button" className="pt__tile" onClick={() => onTask("reset")}>
          <b>Reset password &amp; unlock</b>
          <span>Search for the caller; Enter opens the verified reset sheet directly.</span>
        </button>
        <button type="button" className="pt__tile" onClick={() => onTask("lookup")}>
          <b>Look up an account</b>
          <span>Status, lock source, groups and history in one page.</span>
        </button>
      </div>
      <h2>Recently opened</h2>
      <ul className="pt__list">
        {NAMED.map((u) => (
          <li key={u.sam}>
            <button type="button" className="pt__row" onClick={() => onRecent(u)}>
              <span className="pt__name">{u.name}</span>
              <span className="diq-mono pt__sub">{u.sam}</span>
              <Chips u={u} fixed={null} />
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}

function SearchOverlay(props: {
  readonly directory: readonly SampleUser[];
  readonly query: string;
  readonly setQuery: (q: string) => void;
  readonly intent: Intent | null;
  readonly latencyMs: number;
  readonly failFirst: boolean;
  readonly onFirstType: () => void;
  readonly onPick: (u: SampleUser) => void;
  readonly onClose: () => void;
}) {
  const { directory, query, setQuery, intent, latencyMs, failFirst, onFirstType, onPick, onClose } =
    props;
  const listId = useId();
  const typed = useRef(false);
  const failed = useRef(failFirst);
  const [state, setState] = useState<"idle" | "loading" | "error" | "done">("idle");
  const [result, setResult] = useState<{ hits: SampleUser[]; total: number }>({
    hits: [],
    total: 0,
  });
  const [active, setActive] = useState(0);
  const [attempt, setAttempt] = useState(0);
  const trimmed = query.trim();

  useEffect(() => {
    if (!trimmed) {
      setState("idle");
      return;
    }
    setState("loading");
    const id = setTimeout(() => {
      if (failed.current) {
        failed.current = false;
        setState("error");
        return;
      }
      setResult(searchUsers(directory, trimmed));
      setActive(0);
      setState("done");
    }, latencyMs);
    return () => clearTimeout(id);
  }, [trimmed, directory, latencyMs, attempt]);

  const key = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
    else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, result.hits.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter" && state === "done") {
      // Stop this keypress from also submitting the sheet that opens (and takes focus) next.
      e.preventDefault();
      const u = result.hits[active];
      if (u) onPick(u);
    }
  };

  return (
    <div
      className="pt__scrim"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
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
          aria-expanded={state === "done"}
          aria-controls={listId}
          aria-activedescendant={
            state === "done" && result.hits[active] ? `${listId}-${active}` : undefined
          }
          aria-label="Search users"
          placeholder={
            intent === "reset"
              ? "Who is calling? Enter opens the reset sheet"
              : "Name, sAMAccountName, UPN or e-mail"
          }
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(e) => {
            if (!typed.current) {
              typed.current = true;
              onFirstType();
            }
            setQuery(e.target.value);
          }}
        />
        <div aria-live="polite">
          {state === "idle" ? (
            <p className="pt__msg">
              Try “priya r”, “p.raman”, “li.wei” or “johanna”. Searching{" "}
              {DOMAIN_USER_COUNT.toLocaleString("en")} sample users.
            </p>
          ) : null}
          {state === "loading" ? (
            <div aria-label="Searching" role="status">
              {[0, 1, 2].map((i) => (
                <div key={i} className="pt__skel" />
              ))}
            </div>
          ) : null}
          {state === "error" ? (
            <p className="pt__msg">
              <span className="pt__err">Search is unavailable (sample error). </span>
              Nothing was changed.{" "}
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setAttempt((a) => a + 1);
                }}
              >
                Retry
              </button>
            </p>
          ) : null}
          {state === "done" && result.total === 0 ? (
            <p className="pt__msg">
              No user matches “{trimmed}” among {DOMAIN_USER_COUNT.toLocaleString("en")}. Search
              checks name, account name, UPN and e-mail; try fewer letters.
            </p>
          ) : null}
        </div>
        {state === "done" && result.total > 0 ? (
          <ul className="pt__list" role="listbox" id={listId} aria-label="Users">
            {result.hits.map((u, i) => (
              <li key={u.sam} role="presentation">
                <div
                  role="option"
                  id={`${listId}-${i}`}
                  aria-selected={i === active}
                  tabIndex={-1}
                  className="pt__row"
                  onMouseEnter={() => setActive(i)}
                  onClick={() => onPick(u)}
                >
                  <span className="pt__name">{u.name}</span>
                  <span className="diq-mono pt__sub">{u.sam}</span>
                  <Chips u={u} fixed={null} />
                </div>
              </li>
            ))}
          </ul>
        ) : null}
        <div className="pt__hint">
          {state === "done" && result.total > RESULT_LIMIT
            ? `Showing ${RESULT_LIMIT} of ${result.total} matches. Add a letter to narrow. `
            : ""}
          ↑↓ move · Enter {intent === "reset" ? "opens reset & unlock" : "opens the account"} · Esc
          closes
        </div>
      </div>
    </div>
  );
}

function ObjectView({
  user,
  unlockedAt,
  onReset,
}: {
  readonly user: SampleUser;
  readonly unlockedAt: string | null;
  readonly onReset: () => void;
}) {
  const [tab, setTab] = useState<"overview" | "groups" | "history">("overview");
  const [toast, setToast] = useState("");
  const link = `/users/${encodeURIComponent(user.sam)}`;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(link);
      setToast("Link copied");
    } catch {
      setToast(`Copy blocked by the browser. Link: ${link}`);
    }
    setTimeout(() => setToast(""), 2500);
  };
  const locked = user.lockedSince !== null && unlockedAt === null;
  const tabs = [
    ["overview", "Overview"],
    ["groups", `Groups (${user.groups.length})`],
    ["history", "History"],
  ] as const;
  return (
    <>
      <div className="pt__head">
        <div>
          <h1>{user.name}</h1>
          <p className="pt__sub">
            <span className="diq-mono">{user.sam}</span> · {user.title} ·{" "}
            <span className="diq-mono">{link}</span>
          </p>
          <div className="pt__actions">
            <Chips u={user} fixed={unlockedAt} />
          </div>
        </div>
        <div className="pt__actions">
          <button
            type="button"
            className="btn btn--primary"
            onClick={onReset}
            aria-keyshortcuts="r"
          >
            Reset &amp; unlock <span className="pt__kbd">R</span>
          </button>
          <button type="button" className="btn" onClick={copy}>
            Copy link
          </button>
        </div>
      </div>
      {locked ? (
        <div className="pt__banner" role="alert">
          <strong>⚠ Locked out {user.lockouts}× today.</strong> Last from{" "}
          <span className="diq-mono">{user.lockSource}</span>, since {user.lockedSince}. The
          locked-out source is why a password reset alone often does not help.
        </div>
      ) : null}
      {unlockedAt !== null ? (
        <div className="pt__banner pt__banner--ok" role="status">
          <strong>✓ Password reset and unlocked at {unlockedAt}</strong> by you, verified by code.
          See History.
        </div>
      ) : null}
      <div className="pt__tabs" role="tablist" aria-label="Account sections">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            id={`tab-${id}`}
            aria-selected={tab === id}
            aria-controls="tabpanel"
            className="pt__tab"
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === "overview" ? (
          <dl>
            <dt>UPN</dt>
            <dd className="diq-mono">{user.upn}</dd>
            <dt>E-mail</dt>
            <dd>{user.mail}</dd>
            <dt>Manager</dt>
            <dd>{user.manager}</dd>
            <dt>Code sent to</dt>
            <dd>{user.phone}</dd>
            <dt>Distinguished name</dt>
            <dd className="diq-mono">{user.dn}</dd>
          </dl>
        ) : null}
        {tab === "groups" ? (
          <ul className="pt__list">
            {user.groups.map((g) => (
              <li key={g} className="pt__row" style={{ cursor: "default" }}>
                {g}
              </li>
            ))}
          </ul>
        ) : null}
        {tab === "history" ? (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
              </tr>
            </thead>
            <tbody>
              {unlockedAt !== null ? (
                <tr>
                  <td className="diq-mono">{SAMPLE_TIME}</td>
                  <td>You (sample technician)</td>
                  <td>Password reset and unlocked · verified by code</td>
                </tr>
              ) : null}
              {user.history.map((h) => (
                <tr key={h.when + h.what}>
                  <td className="diq-mono">{h.when}</td>
                  <td>{h.who}</td>
                  <td>{h.what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
      {toast ? (
        <div className="pt__toast" role="status">
          {toast}
        </div>
      ) : null}
    </>
  );
}

type Phase = "verify" | "blocked" | "pending" | "done";

function ResetSheet(props: {
  readonly user: SampleUser;
  readonly alreadyUnlocked: boolean;
  readonly onCodeTyped: () => void;
  readonly onConfirm: () => void;
  readonly onDone: (unlocked: boolean) => void;
  readonly onClose: () => void;
}) {
  const { user, alreadyUnlocked, onCodeTyped, onConfirm, onDone, onClose } = props;
  const [phase, setPhase] = useState<Phase>("verify");
  const [code, setCode] = useState("");
  const [wrong, setWrong] = useState(0);
  const [error, setError] = useState("");
  const [resent, setResent] = useState(false);
  const [mustChange, setMustChange] = useState(true);
  const [unlock, setUnlock] = useState(true);
  const [typedSam, setTypedSam] = useState("");
  const [seed] = useState(3);
  const [pwShown, setPwShown] = useState(true);
  const [copied, setCopied] = useState("");
  const typed = useRef(false);
  const first = useRef<HTMLInputElement>(null);
  const canUnlock = user.lockedSince !== null && !alreadyUnlocked;
  const pw = samplePassphrase(seed + user.sam.length);

  useEffect(() => {
    first.current?.focus();
  }, [phase]);
  const esc = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (user.access === "privileged") {
      if (typedSam !== user.sam) {
        setError(`Type ${user.sam} exactly to continue.`);
        return;
      }
      onConfirm();
      setPhase("pending");
      return;
    }
    if (user.factor === "none") {
      onConfirm();
      setPhase("pending");
      return;
    }
    onConfirm();
    if (code.length !== 6) {
      setError("Enter the 6-digit code the caller reads from their phone.");
      return;
    }
    if (code !== SAMPLE_CODE) {
      const n = wrong + 1;
      setWrong(n);
      setCode("");
      if (n >= 3) {
        setPhase("blocked");
        return;
      }
      setError(
        `That code does not match. ${3 - n} attempt${3 - n === 1 ? "" : "s"} left. Ask the caller to read it again.`,
      );
      return;
    }
    setPhase("done");
  };

  const copy = async (what: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(`${what} copied`);
    } catch {
      setCopied("Copy blocked by the browser");
    }
  };

  const title = `Reset password${canUnlock ? " & unlock" : ""}`;
  return (
    <div
      className="pt__sheetwrap"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="pt__sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sheet-title"
        onKeyDown={esc}
      >
        <form className="pt__form" onSubmit={submit}>
          <div>
            <h2 id="sheet-title">{title}</h2>
            <div className="pt__sub">
              {user.name} · <span className="diq-mono">{user.sam}</span>
            </div>
          </div>

          {user.access === "denied" ? (
            <>
              <div className="pt__box" role="alert">
                <strong>You cannot reset this account.</strong>
                <p>
                  Your help-desk role covers London and Mumbai staff.{" "}
                  <span className="diq-mono">OU=Shanghai</span> is delegated to{" "}
                  <strong>Shanghai IT Service Desk</strong>. Nothing was changed.
                </p>
              </div>
              <div className="pt__actions">
                <button type="button" className="btn" onClick={onClose} autoFocus>
                  Close
                </button>
              </div>
            </>
          ) : null}

          {user.access !== "denied" && phase === "verify" && user.access === "privileged" ? (
            <>
              <div className="pt__box" role="alert">
                <strong>★ Protected account.</strong> Member of{" "}
                <span className="diq-mono">Server Operators</span>. A reset needs a second approver
                and a typed confirmation. The caller code alone is not enough.
              </div>
              <div className="pt__field">
                <label htmlFor="confirm-sam">
                  Type <span className="diq-mono">{user.sam}</span> to request the reset
                </label>
                <input
                  id="confirm-sam"
                  ref={first}
                  className="pt__code"
                  style={{ width: "100%", letterSpacing: "normal" }}
                  value={typedSam}
                  onChange={(e) => {
                    setTypedSam(e.target.value);
                    setError("");
                  }}
                  autoComplete="off"
                  spellCheck={false}
                />
                {error ? (
                  <span className="pt__err" role="alert">
                    {error}
                  </span>
                ) : null}
              </div>
              <div className="pt__actions">
                <button type="submit" className="btn btn--danger">
                  Request second approver
                </button>
                <button type="button" className="btn" onClick={onClose}>
                  Cancel
                </button>
              </div>
            </>
          ) : null}

          {user.access === "ok" && user.factor === "none" && phase === "verify" ? (
            <>
              <div className="pt__box" role="alert">
                <strong>No phone or authenticator enrolled for this person.</strong> The code cannot
                be sent. Ask their manager, {user.manager}, to approve; the request is logged and
                expires after 15 minutes.
              </div>
              <div className="pt__actions">
                <button type="submit" className="btn btn--primary" autoFocus>
                  Request approval from {user.manager}
                </button>
                <button type="button" className="btn" onClick={onClose}>
                  Cancel
                </button>
              </div>
            </>
          ) : null}

          {user.access === "ok" && user.factor === "sms" && phase === "verify" ? (
            <>
              <div className="pt__box">
                <strong>This will:</strong>
                <ul>
                  <li>
                    set a new generated passphrase on <span className="diq-mono">{user.sam}</span>
                  </li>
                  {mustChange ? <li>require a change at next sign-in</li> : null}
                  {canUnlock && unlock ? (
                    <li>unlock the account (locked since {user.lockedSince})</li>
                  ) : null}
                </ul>
              </div>
              <div className="pt__field">
                <label htmlFor="code">Caller verification: code sent to {user.phone}</label>
                <input
                  id="code"
                  ref={first}
                  className="pt__code"
                  inputMode="numeric"
                  maxLength={6}
                  autoComplete="off"
                  value={code}
                  aria-describedby="code-help"
                  onChange={(e) => {
                    if (!typed.current) {
                      typed.current = true;
                      onCodeTyped();
                    }
                    setCode(e.target.value.replace(/\D/g, ""));
                    setError("");
                  }}
                />
                <span id="code-help" className="pt__sub">
                  {resent ? "New code sent. " : "Code sent when this sheet opened. "}Sample: the
                  caller’s phone shows <span className="diq-mono">{SAMPLE_CODE}</span>.
                </span>
                {error ? (
                  <span className="pt__err" role="alert">
                    {error}
                  </span>
                ) : null}
              </div>
              <div className="pt__check">
                <input
                  id="mc"
                  type="checkbox"
                  checked={mustChange}
                  onChange={(e) => setMustChange(e.target.checked)}
                />
                <label htmlFor="mc">Must change password at next sign-in</label>
              </div>
              {canUnlock ? (
                <div className="pt__check">
                  <input
                    id="ul"
                    type="checkbox"
                    checked={unlock}
                    onChange={(e) => setUnlock(e.target.checked)}
                  />
                  <label htmlFor="ul">Unlock the account</label>
                </div>
              ) : null}
              <div className="pt__actions">
                <button type="submit" className="btn btn--primary">
                  {canUnlock && unlock ? "Reset & unlock" : "Reset password"}{" "}
                  <span className="pt__kbd" style={{ color: "inherit" }}>
                    Enter
                  </span>
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setResent(true);
                    setCode("");
                    setError("");
                  }}
                >
                  Send a new code
                </button>
                <button type="button" className="btn" onClick={onClose}>
                  Cancel
                </button>
              </div>
            </>
          ) : null}

          {phase === "blocked" ? (
            <>
              <div className="pt__box" role="alert">
                <strong className="pt__err">Verification blocked.</strong> Three wrong codes. No
                password was changed. This attempt is logged with your name and the time (
                {SAMPLE_TIME}); further attempts on this account are paused for 15 minutes. If the
                caller cannot read the code, ask their manager to approve instead.
              </div>
              <div className="pt__actions">
                <button type="button" className="btn" onClick={onClose} autoFocus>
                  Close
                </button>
              </div>
            </>
          ) : null}

          {phase === "pending" ? (
            <>
              <div className="pt__box" role="status">
                <strong>
                  Waiting for {user.access === "privileged" ? "a second approver" : user.manager}.
                </strong>{" "}
                Request logged {SAMPLE_TIME}. You will see the result on this account’s History;
                nothing has changed yet.
              </div>
              <div className="pt__actions">
                <button type="button" className="btn" onClick={onClose} autoFocus>
                  Back to account
                </button>
              </div>
            </>
          ) : null}

          {phase === "done" ? (
            <>
              <div className="pt__box" role="status">
                <strong>
                  ✓ Password reset{canUnlock && unlock ? " and account unlocked" : ""}.
                </strong>{" "}
                Read it to the caller now; it is not shown again.
              </div>
              <div>
                <div className="pt__pw" aria-label="New password">
                  {pwShown ? pw : "••••••••••••••••"}
                </div>
                {pwShown ? <p className="pt__sub">{phonetic(pw)}</p> : null}
              </div>
              <div className="pt__actions">
                <button type="button" className="btn" onClick={() => copy("Password", pw)}>
                  Copy password
                </button>
                <button type="button" className="btn" onClick={() => setPwShown((s) => !s)}>
                  {pwShown ? "Hide" : "Show"}
                </button>
              </div>
              {copied ? (
                <p role="status" className="pt__sub">
                  {copied}
                </p>
              ) : null}
              <p className="pt__sub">
                Audit: reset{canUnlock && unlock ? " + unlock" : ""} · {user.sam} · by you (sample
                technician) · {SAMPLE_TIME} · verified by code to {user.phone}
                {mustChange ? " · must change at next sign-in" : ""}
              </p>
              <div className="pt__actions">
                <button
                  type="button"
                  className="btn btn--primary"
                  autoFocus
                  onClick={() => onDone(canUnlock && unlock)}
                >
                  Done
                </button>
              </div>
            </>
          ) : null}
        </form>
      </div>
    </div>
  );
}
