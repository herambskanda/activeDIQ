import { type FormEvent, useEffect, useId, useMemo, useRef, useState } from "react";

import { api } from "../../api/client";
import { navigate, useLocation } from "../../app/location";
import {
  Button,
  Chip,
  type Column,
  SegmentedControl,
  Skeleton,
  StatePanel,
  Table,
  TextInput,
} from "../../ds/components";
import "./search-results.css";
import { RouteLink } from "./route-link";
import {
  disambiguatorOf,
  chipView,
  hitHref,
  identifiersOf,
  PAGE_SIZE,
  searchHref,
  segmentsOf,
  type SearchGroup,
  type SearchHit,
  type SearchResult,
  TYPES,
  typeOf,
  validateSearchText,
} from "./search-results-model";
import { type ApiClient, useDirectorySearch } from "./use-directory-search";

/** How long typing must pause before the search is sent. */
export const DEBOUNCE_MS = 300;

const ALL = "all";
const SINGULAR: Readonly<Record<string, string>> = {
  users: "User",
  groups: "Group",
  computers: "Computer",
  contacts: "Contact",
};
const PLURAL = (type: string) => TYPES.find((t) => t.value === type)?.label.toLowerCase() ?? type;

/**
 * The full results page ("Show all", IA 5.7): every permitted hit of one search, filterable by
 * type, paged by the server. The text and the type live in the address bar so a search can be
 * bookmarked and stepped through with back and forward. Every value shown is a field of the API's
 * answer; the page has no data of its own.
 */
export function SearchResultsPage({ client = api }: { readonly client?: ApiClient }) {
  const { search } = useLocation();
  const urlQ = search.get("q") ?? "";
  const type = typeOf(search.get("type"));
  // A refused text that arrives in the address bar is never sent and is taken out of the URL.
  const urlRefusal = validateSearchText(urlQ.trim());
  const committed = urlRefusal === undefined ? urlQ.trim() : "";

  const [text, setText] = useState(urlRefusal === undefined ? urlQ : "");
  const [notice, setNotice] = useState<string | undefined>(urlRefusal);
  const input = useRef<HTMLInputElement>(null);
  const resultsId = useId();

  // Back and forward change the address; the box follows it.
  useEffect(() => {
    if (urlRefusal !== undefined) {
      setNotice(urlRefusal);
      setText("");
      const kept = typeOf(new URLSearchParams(window.location.search).get("type"));
      navigate(searchHref("", kept), { replace: true });
    } else {
      setText((typed) => (typed.trim() === urlQ ? typed : urlQ));
    }
  }, [urlQ, urlRefusal]);

  const trimmed = text.trim();
  const invalid = validateSearchText(trimmed) ?? notice;

  // Debounce: move to the typed text once typing pauses. Refused text is never put in the address.
  useEffect(() => {
    if (validateSearchText(trimmed) !== undefined || trimmed === committed) return;
    const timer = setTimeout(() => navigate(searchHref(trimmed, type)), DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [trimmed, committed, type]);

  const { state, retry, page, next, previous, first, counts } = useDirectorySearch(
    client,
    committed,
    type,
  );

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (validateSearchText(trimmed) === undefined) navigate(searchHref(trimmed, type));
  };
  const clear = () => {
    setText("");
    setNotice(undefined);
    navigate(searchHref("", type));
    input.current?.focus();
  };

  const options = [
    { value: ALL, label: "All" },
    ...TYPES.map((t) => {
      const n = counts[t.value];
      return { value: t.value, label: n === undefined ? t.label : `${t.label} (${n})` };
    }),
  ];

  return (
    <main className="diq-page">
      <h1 className="diq-page__title">Search</h1>
      <form role="search" onSubmit={submit}>
        <TextInput
          label="Search the directory"
          inputRef={input}
          type="search"
          autoComplete="off"
          spellCheck={false}
          placeholder="Name, account name, e-mail, SID, GUID, DN or host name"
          value={text}
          error={invalid}
          onChange={(e) => {
            setNotice(undefined);
            setText(e.target.value);
          }}
          trailing={text !== "" && <Button onClick={clear}>Clear</Button>}
        />
      </form>

      <div className="sr-filter">
        <SegmentedControl
          label="Type"
          name="type"
          options={options}
          value={type ?? ALL}
          onChange={(v) => {
            if (v === null) return;
            navigate(searchHref(committed, typeOf(v)));
          }}
        />
      </div>

      <section aria-labelledby={`${resultsId}-results`} aria-busy={state.status === "loading"}>
        <h2 id={`${resultsId}-results`} className="diq-sr-only">
          Results
        </h2>
        {state.status === "idle" && (
          <StatePanel>
            Type a name, account name, e-mail, SID, GUID, distinguished name or host name to search
            everything you may see.
          </StatePanel>
        )}
        {state.status === "loading" && <Skeleton label="Searching" rows={8} />}
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
            q={committed}
            type={type}
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
  type,
  page,
  next,
  previous,
  clear,
}: {
  readonly result: SearchResult;
  readonly q: string;
  readonly type: ReturnType<typeof typeOf>;
  readonly page: number;
  readonly next: (() => void) | undefined;
  readonly previous: (() => void) | undefined;
  readonly clear: () => void;
}) {
  const hits = result.groups.flatMap((g) => g.items);
  const showDomain = hits.some((h) => h.domain !== "");
  const columns = useMemo(() => columnsOf(showDomain), [showDomain]);

  if (hits.length === 0) {
    return result.refine ? (
      <StatePanel title="Keep typing to narrow the search">
        <p>Too many objects match this text to rank them. Add more of the name or identifier.</p>
        <Button onClick={clear}>Clear search</Button>
      </StatePanel>
    ) : (
      <StatePanel title={`No objects match “${shorten(q)}” in your scope`}>
        <p>
          Check the spelling, or try an account name, e-mail address or host name. If you expected a
          result, your scope may not cover it: ask your activeDIQ administrator.
        </p>
        <Button onClick={clear}>Clear search</Button>
      </StatePanel>
    );
  }

  const chosen = type === undefined ? undefined : result.groups.find((g) => g.type === type);
  const moreGroups = type === undefined ? result.groups.filter((g) => g.more === true) : [];
  return (
    <>
      <p className="diq-hint" role="status">
        {summaryOf(hits.length, chosen, page, type)}
      </p>
      {result.refine && (
        <StatePanel title="Keep typing to narrow the search">
          <p>
            Too many objects match this text to rank them, so counts are not shown. Closer matches
            are listed below.
          </p>
        </StatePanel>
      )}
      <Table
        caption="Search results"
        columns={columns}
        rows={hits}
        rowKey={(h) => `${h.type}:${h.objectId}`}
      />
      {moreGroups.length > 0 && (
        <ul className="sr-more">
          {moreGroups.map((g) => (
            <li key={g.type}>
              <RouteLink to={searchHref(q, typeOf(g.type))}>
                {g.count === undefined
                  ? `Show all ${PLURAL(g.type)}`
                  : `Show all ${g.count} ${PLURAL(g.type)}`}
              </RouteLink>
            </li>
          ))}
        </ul>
      )}
      {chosen?.limitReached === true && (
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

function summaryOf(
  shown: number,
  group: SearchGroup | undefined,
  page: number,
  type: ReturnType<typeof typeOf>,
): string {
  if (group === undefined || type === undefined) {
    return `${shown} ${shown === 1 ? "result" : "results"} shown.`;
  }
  const from = (page - 1) * PAGE_SIZE + 1;
  const to = from + shown - 1;
  const of = group.count === undefined ? "" : ` of ${group.count}`;
  return `Showing ${from}–${to}${of} ${PLURAL(type)}.`;
}

function Marked({
  text,
  field,
  hit,
}: {
  readonly text: string;
  readonly field: Parameters<typeof segmentsOf>[1];
  readonly hit: SearchHit;
}) {
  return (
    <>
      {segmentsOf(text, field, hit.highlights).map((s, i) =>
        s.match ? (
          <mark key={i} className="sr-mark">
            {s.text}
          </mark>
        ) : (
          <span key={i}>{s.text}</span>
        ),
      )}
    </>
  );
}

function columnsOf(showDomain: boolean): readonly Column<SearchHit>[] {
  const cols: Column<SearchHit>[] = [
    { key: "type", header: "Type", cell: (h) => SINGULAR[h.type] ?? h.type },
    {
      key: "name",
      header: "Name",
      rowHeader: true,
      cell: (h) => {
        const name = <Marked text={h.displayName} field="displayName" hit={h} />;
        const href = hitHref(h);
        return href === undefined ? name : <RouteLink to={href}>{name}</RouteLink>;
      },
      title: (h) => h.displayName,
    },
    {
      key: "identifiers",
      header: "Identifiers",
      mono: true,
      cell: (h) => (
        <>
          {identifiersOf(h).map((id, i) => (
            <span key={id}>
              {i > 0 && " · "}
              <Marked text={id} field={fieldOf(h, id)} hit={h} />
            </span>
          ))}
        </>
      ),
      title: (h) => identifiersOf(h).join(" · "),
    },
    {
      key: "status",
      header: "Status",
      cell: (h) => (
        <span className="sr-chips">
          {h.status.flatMap((c, i) => {
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
      cell: (h) => disambiguatorOf(h),
      title: disambiguatorOf,
    },
    {
      key: "dn",
      header: "Distinguished name",
      mono: true,
      cell: (h) => h.distinguishedName,
      title: (h) => h.distinguishedName,
    },
  ];
  if (showDomain) {
    cols.push({
      key: "domain",
      header: "Domain",
      mono: true,
      cell: (h) => h.domain,
      title: (h) => h.domain,
    });
  }
  return cols;
}

/** Which highlight field an identifier of a hit is, so its matched stretch can be marked. */
function fieldOf(
  hit: SearchHit,
  identifier: string,
): "samAccountName" | "userPrincipalName" | "mail" {
  if (hit.samAccountName === identifier) return "samAccountName";
  if (hit.userPrincipalName === identifier) return "userPrincipalName";
  return "mail";
}
