import { useEffect, useState } from "react";

import { api } from "../../api/client";
import { navigate, useLocation } from "../../app/location";
import { Button, Select, Skeleton, StatePanel, TextInput } from "../../ds/components";
import type { ApiClient, DefinitionSummary } from "./api";
import { ReportsFrame } from "./frame";
import { Link } from "./link";
import { CATEGORIES, categoryLabel } from "./model";
import { useDefinitions } from "./use-definitions";

/** How long typing must pause before the library filter is sent. */
export const FILTER_DEBOUNCE_MS = 300;

const hrefOf = (d: DefinitionSummary) => `/reports/${encodeURIComponent(d.id)}`;

function setParams(update: Record<string, string>) {
  const p = new URLSearchParams(window.location.search);
  for (const [k, v] of Object.entries(update)) {
    if (v === "") p.delete(k);
    else p.set(k, v);
  }
  const s = p.toString();
  navigate(`${window.location.pathname}${s === "" ? "" : `?${s}`}`);
}

/**
 * The library (spec §5): reports grouped by category, filtered on the server by name, description
 * and ManageEngine name. It is for browsing; the fast path is `/` search. The filter and category
 * are in the address bar.
 */
export function LibraryPage({ client = api }: { readonly client?: ApiClient }) {
  const { search } = useLocation();
  const q = search.get("q") ?? "";
  const category = search.get("category") ?? "";
  const [text, setText] = useState(q);

  // Back and forward change the address, so the box follows it.
  useEffect(() => setText(q), [q]);
  useEffect(() => {
    const t = text.trim();
    if (t === q) return;
    const timer = setTimeout(() => setParams({ q: t }), FILTER_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [text, q]);

  const { state, retry, loadMore } = useDefinitions(client, { q, category });
  const filtered = q !== "" || category !== "";

  let body;
  if (state.status === "loading") {
    body = <Skeleton label="Loading reports" />;
  } else if (state.status === "failed") {
    body =
      state.failure.kind === "forbidden" ? (
        <StatePanel title={state.failure.title}>
          <p>{state.failure.detail}</p>
        </StatePanel>
      ) : (
        <StatePanel tone="error" title={state.failure.title}>
          <p>{state.failure.detail}</p>
          {state.failure.traceId !== undefined && (
            <p>
              Trace ID <span className="diq-mono">{state.failure.traceId}</span>
            </p>
          )}
          <Button variant="primary" onClick={retry}>
            Retry
          </Button>
        </StatePanel>
      );
  } else if (state.items.length === 0) {
    body = filtered ? (
      <StatePanel
        title={q !== "" ? `No report matches “${q}”` : "No report in this category"}
        actions={
          <Button
            onClick={() => {
              setText("");
              setParams({ q: "", category: "" });
            }}
          >
            Clear filter
          </Button>
        }
      >
        <p>
          Checked report names, descriptions and ManageEngine report names. Try fewer letters, or
          clear the filter to see all reports.
        </p>
      </StatePanel>
    ) : (
      <StatePanel title="No reports are available">
        <p>
          The report library is empty for your role. Ask an administrator whether reports are set up
          for your organisation.
        </p>
      </StatePanel>
    );
  } else {
    const groups = new Map<string, DefinitionSummary[]>();
    for (const d of state.items) groups.set(d.category, [...(groups.get(d.category) ?? []), d]);
    const order = [
      ...CATEGORIES.map((c) => c.id),
      ...[...groups.keys()].filter((k) => !CATEGORIES.some((c) => c.id === k)),
    ];
    body = (
      <>
        {order
          .filter((id) => groups.has(id))
          .map((id) => (
            <section key={id} aria-labelledby={`cat-${id}`} className="rp-lib__group">
              <h2 id={`cat-${id}`} className="rp-lib__cat">
                {categoryLabel(id)}
              </h2>
              <ul className="rp-lib__list">
                {(groups.get(id) ?? []).map((d) => (
                  <li key={d.id} className="rp-lib__row">
                    <div className="rp-lib__name">
                      <Link to={hrefOf(d)}>{d.name}</Link>
                      <span className="rp-lib__desc">{d.description}</span>
                    </div>
                    {d.alsoKnownAs.length > 0 && (
                      <span
                        className="rp-lib__aka"
                        title={d.alsoKnownAs.map((m) => m.meName).join(", ")}
                      >
                        Also known as:{" "}
                        {d.alsoKnownAs
                          .slice(0, 2)
                          .map((m) => m.meName)
                          .join(", ")}
                        {d.alsoKnownAs.length > 2 ? ` +${d.alsoKnownAs.length - 2} more` : ""}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        {state.more && (
          <Button loading={state.loadingMore} onClick={loadMore}>
            Load more reports
          </Button>
        )}
      </>
    );
  }

  return (
    <ReportsFrame client={client}>
      <form role="search" className="rp-lib__filter" onSubmit={(e) => e.preventDefault()}>
        <TextInput
          label="Filter reports"
          type="search"
          autoComplete="off"
          spellCheck={false}
          placeholder="Report name, ManageEngine name or description"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <Select
          label="Category"
          placeholder="All categories"
          options={CATEGORIES.map((c) => ({ value: c.id, label: c.label }))}
          value={category}
          onChange={(v) => setParams({ category: v })}
        />
      </form>
      <section aria-busy={state.status === "loading"} aria-label="Reports">
        {body}
      </section>
    </ReportsFrame>
  );
}
