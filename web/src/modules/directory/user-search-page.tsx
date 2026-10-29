import { type FormEvent, useEffect, useId, useRef } from "react";

import { api } from "../../api/client";
import { SEARCH_LIMIT, validateQuery } from "./search-model";
import { type ApiClient, type DirectoryUser, useUserSearch } from "./use-user-search";
import { useQueryInUrl } from "./use-query-in-url";
import "./user-search-page.css";

/** How long typing must pause before the search is sent. */
export const DEBOUNCE_MS = 300;
const SKELETON_ROWS = 6;

export function UserSearchPage({ client = api }: { readonly client?: ApiClient }) {
  const { text, setText, committed, commit } = useQueryInUrl();
  const inputId = useId();
  const problemId = useId();
  const input = useRef<HTMLInputElement>(null);

  const trimmed = text.trim();
  const invalid = validateQuery(trimmed);

  // Debounce: send the search once typing pauses. Invalid text is never sent.
  useEffect(() => {
    if (invalid !== undefined || trimmed === committed) return;
    const timer = setTimeout(() => commit(trimmed), DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [trimmed, invalid, committed, commit]);

  const { state, retry } = useUserSearch(client, committed);

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
    <main className="diq-search">
      <h1 className="diq-search__title">Users</h1>
      <form className="diq-search__form" role="search" onSubmit={submit}>
        <label className="diq-search__label" htmlFor={inputId}>
          Search users
        </label>
        <div className="diq-search__field">
          <input
            ref={input}
            id={inputId}
            className="diq-search__input"
            type="search"
            autoComplete="off"
            spellCheck={false}
            placeholder="Name, account name or user principal name"
            value={text}
            aria-invalid={invalid !== undefined}
            aria-describedby={invalid === undefined ? undefined : problemId}
            onChange={(e) => setText(e.target.value)}
          />
          {text !== "" && (
            <button type="button" className="diq-btn" onClick={clear}>
              Clear
            </button>
          )}
        </div>
        {invalid !== undefined && (
          <p id={problemId} className="diq-search__field-error">
            {invalid}
          </p>
        )}
      </form>

      <section aria-labelledby={`${inputId}-results`} aria-busy={state.status === "loading"}>
        <h2 id={`${inputId}-results`} className="diq-sr-only">
          Results
        </h2>
        {state.status === "idle" && (
          <p className="diq-state">
            Type a name, account name or user principal name to find users.
          </p>
        )}
        {state.status === "loading" && <Skeleton />}
        {state.status === "failed" && (
          <div className="diq-state diq-state--error" role="alert">
            <p className="diq-state__title">{state.failure.title}</p>
            <p>{state.failure.detail}</p>
            {state.failure.traceId !== undefined && (
              <p>
                Trace ID <span className="diq-mono">{state.failure.traceId}</span>
              </p>
            )}
            {state.failure.kind !== "denied" && (
              <button type="button" className="diq-btn diq-btn--primary" onClick={retry}>
                Retry
              </button>
            )}
          </div>
        )}
        {state.status === "done" && state.users.length === 0 && (
          <div className="diq-state">
            <p className="diq-state__title">No users match “{committed}”</p>
            <p>Check the spelling, or try part of the account name or user principal name.</p>
            <button type="button" className="diq-btn" onClick={clear}>
              Clear search
            </button>
          </div>
        )}
        {state.status === "done" && state.users.length > 0 && <Results users={state.users} />}
      </section>
    </main>
  );
}

function Results({ users }: { readonly users: readonly DirectoryUser[] }) {
  const capped = users.length >= SEARCH_LIMIT;
  return (
    <>
      <p className="diq-search__count" role="status">
        {capped
          ? `Showing the first ${users.length} matches. Type more to narrow the search.`
          : `${users.length} ${users.length === 1 ? "user" : "users"} found.`}
      </p>
      <table className="diq-table">
        <caption className="diq-sr-only">Matching users</caption>
        <thead>
          <tr>
            <th scope="col">Display name</th>
            <th scope="col">Account name</th>
            <th scope="col">User principal name</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.objectGuid}>
              <th scope="row">{u.displayName}</th>
              <td className="diq-mono">{u.samAccountName}</td>
              <td className="diq-mono">{u.userPrincipalName}</td>
              <td>
                <span className={`diq-chip ${u.enabled ? "diq-chip--ok" : "diq-chip--muted"}`}>
                  {u.enabled ? "Enabled" : "Disabled"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Skeleton() {
  return (
    <div className="diq-skeleton" role="status" aria-label="Searching">
      {Array.from({ length: SKELETON_ROWS }, (_, i) => (
        <div key={i} className="diq-skeleton__row" />
      ))}
    </div>
  );
}
