import { type FormEvent, useEffect, useId, useRef } from "react";

import {
  Button,
  Chip,
  type Column,
  Skeleton,
  StatePanel,
  Table,
  TextInput,
} from "../../ds/components";
import { api } from "../../api/client";
import { SEARCH_LIMIT, validateQuery } from "./search-model";
import { type ApiClient, type DirectoryUser, useUserSearch } from "./use-user-search";
import { useQueryInUrl } from "./use-query-in-url";

/** How long typing must pause before the search is sent. */
export const DEBOUNCE_MS = 300;

export function UserSearchPage({ client = api }: { readonly client?: ApiClient }) {
  const { text, setText, committed, commit } = useQueryInUrl();
  const resultsId = useId();
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
    <main className="diq-page">
      <h1 className="diq-page__title">Users</h1>
      <form role="search" onSubmit={submit}>
        <TextInput
          label="Search users"
          inputRef={input}
          type="search"
          autoComplete="off"
          spellCheck={false}
          placeholder="Name, account name or user principal name"
          value={text}
          error={invalid}
          onChange={(e) => setText(e.target.value)}
          trailing={text !== "" && <Button onClick={clear}>Clear</Button>}
        />
      </form>

      <section aria-labelledby={`${resultsId}-results`} aria-busy={state.status === "loading"}>
        <h2 id={`${resultsId}-results`} className="diq-sr-only">
          Results
        </h2>
        {state.status === "idle" && (
          <StatePanel>Type a name, account name or user principal name to find users.</StatePanel>
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
            {state.failure.kind !== "denied" && state.failure.kind !== "unauthenticated" && (
              <Button variant="primary" onClick={retry}>
                Retry
              </Button>
            )}
          </StatePanel>
        )}
        {state.status === "done" && state.users.length === 0 && (
          <StatePanel title={`No users match “${committed}”`}>
            <p>Check the spelling, or try part of the account name or user principal name.</p>
            <Button onClick={clear}>Clear search</Button>
          </StatePanel>
        )}
        {state.status === "done" && state.users.length > 0 && <Results users={state.users} />}
      </section>
    </main>
  );
}

const COLUMNS: readonly Column<DirectoryUser>[] = [
  {
    key: "name",
    header: "Display name",
    rowHeader: true,
    cell: (u) => u.displayName,
    title: (u) => u.displayName,
  },
  {
    key: "sam",
    header: "Account name",
    mono: true,
    cell: (u) => u.samAccountName,
    title: (u) => u.samAccountName,
  },
  {
    key: "upn",
    header: "User principal name",
    mono: true,
    cell: (u) => u.userPrincipalName,
    title: (u) => u.userPrincipalName,
  },
  {
    key: "status",
    header: "Status",
    cell: (u) => (
      <Chip tone={u.enabled ? "ok" : "muted"}>{u.enabled ? "Enabled" : "Disabled"}</Chip>
    ),
  },
];

function Results({ users }: { readonly users: readonly DirectoryUser[] }) {
  const capped = users.length >= SEARCH_LIMIT;
  return (
    <>
      <p className="diq-hint" role="status">
        {capped
          ? `Showing the first ${users.length} matches. Type more to narrow the search.`
          : `${users.length} ${users.length === 1 ? "user" : "users"} found.`}
      </p>
      <Table caption="Matching users" columns={COLUMNS} rows={users} rowKey={(u) => u.objectGuid} />
    </>
  );
}
