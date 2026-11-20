import { type FormEvent, useEffect, useId, useMemo, useRef } from "react";

import { api } from "../../api/client";
import {
  Button,
  Chip,
  type Column,
  Skeleton,
  StatePanel,
  Table,
  TextInput,
} from "../../ds/components";
import "./search-results.css";
import {
  chipView,
  disambiguatorOf,
  identifiersOf,
  PAGE_SIZE,
  type SearchHit,
  type SearchResult,
  validateSearchText,
} from "./search-results-model";
import { type ApiClient, useDirectorySearch } from "./use-directory-search";
import { useQueryInUrl } from "./use-query-in-url";

/** How long typing must pause before the search is sent. */
export const DEBOUNCE_MS = 300;

/**
 * The user search (/directory/users?q=). It asks directory.search for users only, so it answers
 * from the inventory, trimmed by the caller's ReadScope, and pages by the API's cursor. Every
 * value shown is a field of the API's answer.
 */
export function UserSearchPage({ client = api }: { readonly client?: ApiClient }) {
  const { text, setText, committed, commit } = useQueryInUrl();
  const resultsId = useId();
  const input = useRef<HTMLInputElement>(null);

  const trimmed = text.trim();
  const invalid = validateSearchText(trimmed);
  // A refused text that arrives in the address bar is never sent.
  const toSend = validateSearchText(committed) === undefined ? committed : "";

  // Debounce: send the search once typing pauses. Refused text is never sent.
  useEffect(() => {
    if (invalid !== undefined || trimmed === committed) return;
    const timer = setTimeout(() => commit(trimmed), DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [trimmed, invalid, committed, commit]);

  const { state, retry, page, next, previous, first } = useDirectorySearch(client, toSend, "users");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (invalid === undefined) commit(trimmed);
  };
  const clear = () => {
    setText("");
    commit("");
    input.current?.focus();
  };

  return (
    <main className="diq-page">
      <h1 className="diq-page__title">Users</h1>
      <form role="search" onSubmit={submit}>
        <TextInput
          label="Search users"
          inputRef={input}
          type="search"
          autoComplete="off"
          spellCheck={false}
          placeholder="Name, account name, user principal name or e-mail"
          value={text}
          error={invalid ?? validateSearchText(committed)}
          onChange={(e) => setText(e.target.value)}
          trailing={text !== "" && <Button onClick={clear}>Clear</Button>}
        />
      </form>

      <section aria-labelledby={`${resultsId}-results`} aria-busy={state.status === "loading"}>
        <h2 id={`${resultsId}-results`} className="diq-sr-only">
          Results
        </h2>
        {state.status === "idle" && (
          <StatePanel>
            Type a name, account name, user principal name or e-mail to find users you may see.
          </StatePanel>
        )}
        {state.status === "loading" && <Skeleton label="Searching" />}
        {state.status === "failed" && (
          <StatePanel tone="error" title={state.failure.title}>
            <p>{state.failure.detail}</p>
            {state.failure.traceId !== undefined && (
              <p>
                Trace ID <span className="diq-mono">{state.failure.traceId}</span>
              </p>
            )}
            {state.failure.kind === "unauthenticated" && (
              <Button
                variant="primary"
                onClick={() => {
                  const here = window.location.pathname + window.location.search;
                  window.location.assign(`/sign-in?next=${encodeURIComponent(here)}`);
                }}
              >
                Sign in
              </Button>
            )}
            {(state.failure.kind === "rate-limited" ||
              state.failure.kind === "unreachable" ||
              state.failure.kind === "error") && (
              <Button variant="primary" onClick={retry}>
                Retry
              </Button>
            )}
            {state.failure.kind === "invalid" && first !== undefined && (
              <Button variant="primary" onClick={first}>
                Back to the first page
              </Button>
            )}
            {state.failure.kind === "invalid" && first === undefined && (
              <Button onClick={clear}>Clear search</Button>
            )}
          </StatePanel>
        )}
        {state.status === "done" && (
          <Answer
            result={state.result}
            q={toSend}
            page={page}
            next={next}
            previous={previous}
            clear={clear}
          />
        )}
      </section>
    </main>
  );
}

function Answer({
  result,
  q,
  page,
  next,
  previous,
  clear,
}: {
  readonly result: SearchResult;
  readonly q: string;
  readonly page: number;
  readonly next: (() => void) | undefined;
  readonly previous: (() => void) | undefined;
  readonly clear: () => void;
}) {
  const group = result.groups.find((g) => g.type === "users");
  const users = group?.items ?? [];
  const showDomain = users.some((u) => u.domain !== "");
  const columns = useMemo(() => columnsOf(showDomain), [showDomain]);

  if (users.length === 0) {
    return result.refine ? (
      <StatePanel title="Keep typing to narrow the search">
        <p>Too many users match this text to rank them. Add more of the name or identifier.</p>
        <Button onClick={clear}>Clear search</Button>
      </StatePanel>
    ) : (
      <StatePanel title={`No users match “${shorten(q)}” in your scope`}>
        <p>
          Check the spelling, or try part of the account name, user principal name or e-mail. If you
          expected a result, your scope may not cover it: ask your activeDIQ administrator.
        </p>
        <Button onClick={clear}>Clear search</Button>
      </StatePanel>
    );
  }

  const from = (page - 1) * PAGE_SIZE + 1;
  const to = from + users.length - 1;
  const of = group?.count === undefined ? "" : ` of ${group.count}`;
  return (
    <>
      <p className="diq-hint" role="status">
        {page === 1 && next === undefined
          ? `${users.length} ${users.length === 1 ? "user" : "users"} found.`
          : `Showing ${from}–${to}${of} users.`}
      </p>
      {result.refine && (
        <StatePanel title="Keep typing to narrow the search">
          <p>
            Too many users match this text to rank them, so counts are not shown. Closer matches are
            listed below.
          </p>
        </StatePanel>
      )}
      <Table caption="Matching users" columns={columns} rows={users} rowKey={(u) => u.objectId} />
      {group?.limitReached === true && (
        <p className="diq-hint">
          Showing the first 1,000 matches. Refine your search to see others.
        </p>
      )}
      {(previous !== undefined || next !== undefined) && (
        <nav className="sr-pages" aria-label="Result pages">
          {previous !== undefined && <Button onClick={previous}>Previous page</Button>}
          <span>Page {page}</span>
          {next !== undefined && (
            <Button variant="primary" onClick={next}>
              Next page
            </Button>
          )}
        </nav>
      )}
      <p className="sr-foot">
        {result.asOf === null ? (
          "The directory inventory has not synced yet."
        ) : (
          <>
            Directory inventory as of <time dateTime={result.asOf}>{formatAsOf(result.asOf)}</time>.
          </>
        )}
      </p>
    </>
  );
}

function shorten(q: string): string {
  const chars = Array.from(q);
  return chars.length <= 60 ? q : `${chars.slice(0, 59).join("")}…`;
}

function formatAsOf(at: string): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime())
    ? at
    : d.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
}

function columnsOf(showDomain: boolean): readonly Column<SearchHit>[] {
  const cols: Column<SearchHit>[] = [
    {
      key: "name",
      header: "Display name",
      rowHeader: true,
      cell: (u) => u.displayName,
      title: (u) => u.displayName,
    },
    {
      key: "identifiers",
      header: "Account name · principal name · e-mail",
      mono: true,
      cell: (u) => identifiersOf(u).join(" · "),
      title: (u) => identifiersOf(u).join(" · "),
    },
    {
      key: "status",
      header: "Status",
      cell: (u) => (
        <span className="sr-chips">
          {u.status.flatMap((c, i) => {
            const v = chipView(c);
            return v === undefined
              ? []
              : [
                  <Chip key={`${c.kind}:${i}`} tone={v.tone}>
                    {v.label}
                  </Chip>,
                ];
          })}
        </span>
      ),
    },
    {
      key: "disambiguator",
      header: "Title · office",
      cell: (u) => disambiguatorOf(u),
      title: disambiguatorOf,
    },
    {
      key: "dn",
      header: "Distinguished name",
      mono: true,
      cell: (u) => u.distinguishedName,
      title: (u) => u.distinguishedName,
    },
  ];
  if (showDomain) {
    cols.push({
      key: "domain",
      header: "Domain",
      mono: true,
      cell: (u) => u.domain,
      title: (u) => u.domain,
    });
  }
  return cols;
}
