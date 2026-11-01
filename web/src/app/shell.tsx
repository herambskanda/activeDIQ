import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import "./shell.css";
import { api, type Problem } from "../api/client";
import {
  Button,
  CommandPalette,
  Kbd,
  Skeleton,
  StatePanel,
  type PaletteGroup,
  type PaletteItem,
  type PaletteNotice,
  type PaletteStatus,
} from "../ds/components";
import { collectContributions, matchRoute, type WebModule } from "./modules";
import { loadSession, SIGN_IN_PATH, type SessionClient, safeNext } from "./session";
import { SignInPage } from "./sign-in";
import { navigate } from "./location";
import {
  buildPaletteGroups,
  formatTime,
  isRecoveryPassword,
  QUERY_TTL_MS,
  RECOVERY_PASSWORD_MESSAGE,
  SEARCH_DEBOUNCE_MS,
} from "./palette-wiring";

/** Where the console opens when the address names no screen. */
const HOME_PATH = "/directory/users";

function currentPath(): string {
  return window.location.pathname.replace(/\/+$/, "") || "/";
}

type Session = "checking" | "none" | "active" | "unreachable";

/**
 * The console shell. It checks that a session exists (no session: the sign-in screen, which returns
 * to the requested page), then mounts the screen whose route matches the address, from the routes
 * the registered modules contribute. An address no route matches says so rather than a blank page.
 *
 * When signed in, mounts the top-bar search trigger and the Ctrl+K / '/' universal command palette
 * (T-1101) wired to universal search and registered pages.
 */
export function Shell({
  modules,
  client = api,
}: {
  readonly modules: readonly WebModule[];
  readonly client?: SessionClient;
}) {
  const { routes, palette: registeredPalette } = useMemo(
    () => collectContributions(modules),
    [modules],
  );
  const [path, setPath] = useState(currentPath);
  const [session, setSession] = useState<Session>("checking");

  // Command palette state
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<PaletteStatus>("idle");
  const [groups, setGroups] = useState<readonly PaletteGroup[]>([]);
  const [notice, setNotice] = useState<PaletteNotice | undefined>();
  const [asOf, setAsOf] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);

  const lastQueryTimeRef = useRef<number>(0);
  const requestIdRef = useRef<number>(0);

  const check = useCallback(() => {
    setSession("checking");
    loadSession(client).then(
      (ok) => setSession(ok ? "active" : "none"),
      () => setSession("unreachable"),
    );
  }, [client]);

  useEffect(check, [check]);

  useEffect(() => {
    const onPop = () => setPath(currentPath());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  // No session: move to the sign-in screen, remembering the requested address.
  useEffect(() => {
    if (session !== "none" || path === SIGN_IN_PATH) return;
    const target = path === "/" ? HOME_PATH : window.location.pathname + window.location.search;
    window.history.replaceState(null, "", `${SIGN_IN_PATH}?next=${encodeURIComponent(target)}`);
    setPath(SIGN_IN_PATH);
  }, [session, path]);

  // Signed in but on the sign-in address: go on to the requested page.
  useEffect(() => {
    if (session !== "active" || path !== SIGN_IN_PATH) return;
    const next = safeNext(new URLSearchParams(window.location.search).get("next"), HOME_PATH);
    window.history.replaceState(null, "", next);
    setPath(currentPath());
  }, [session, path]);

  const openPalette = useCallback(() => {
    const now = Date.now();
    // 5-minute TTL: reset query if older than 5 minutes
    if (now - lastQueryTimeRef.current > QUERY_TTL_MS) {
      setQuery("");
      setGroups([]);
      setStatus("idle");
      setNotice(undefined);
    }
    setPaletteOpen(true);
  }, []);

  const closePalette = useCallback(() => {
    setPaletteOpen(false);
  }, []);

  const handleQueryChange = useCallback((newQuery: string) => {
    setQuery(newQuery);
    lastQueryTimeRef.current = Date.now();
  }, []);

  // Global keyboard shortcuts: Ctrl/Cmd+K (toggle) and '/' outside text fields (open)
  useEffect(() => {
    if (session !== "active") return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const mod = (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey;
      const k = e.key.toLowerCase();

      if (mod && k === "k") {
        e.preventDefault();
        setPaletteOpen((wasOpen) => {
          if (!wasOpen) {
            const now = Date.now();
            if (now - lastQueryTimeRef.current > QUERY_TTL_MS) {
              setQuery("");
              setGroups([]);
              setStatus("idle");
              setNotice(undefined);
            }
            return true;
          }
          return false;
        });
        return;
      }

      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const target = e.target;
        const isField =
          target instanceof HTMLElement &&
          (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName));
        if (!isField) {
          e.preventDefault();
          setPaletteOpen((wasOpen) => {
            if (!wasOpen) {
              const now = Date.now();
              if (now - lastQueryTimeRef.current > QUERY_TTL_MS) {
                setQuery("");
                setGroups([]);
                setStatus("idle");
                setNotice(undefined);
              }
              return true;
            }
            return wasOpen;
          });
        }
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [session]);

  // Debounced universal directory search
  useEffect(() => {
    if (!paletteOpen) return;
    const trimmed = query.trim();
    if (trimmed === "") {
      setStatus("idle");
      setGroups([]);
      setNotice(undefined);
      return;
    }

    // AC 5: 48-digit recovery password is refused in browser with IA message and never sent
    if (isRecoveryPassword(trimmed)) {
      setStatus("error");
      setGroups([]);
      setNotice({
        title: "Recovery password refused",
        body: RECOVERY_PASSWORD_MESSAGE,
      });
      return;
    }

    const reqId = ++requestIdRef.current;
    setStatus("loading");
    setNotice(undefined);

    const timer = setTimeout(async () => {
      try {
        const res = await client.POST("/directory/search", {
          body: { q: trimmed },
        });

        // Ignore stale answers (AC 2)
        if (requestIdRef.current !== reqId) return;

        if (!res.response.ok) {
          const prob = res.error as Problem | undefined;
          const traceId = prob?.traceId;
          const traceEl = traceId ? (
            <p>
              Trace ID <span className="diq-mono">{traceId}</span>
            </p>
          ) : null;

          if (res.response.status === 403) {
            setStatus("denied");
            setGroups([]);
            setNotice({
              title: "Search forbidden",
              body: (
                <>
                  <p>You don't have permission to search the directory.</p>
                  {traceEl}
                </>
              ),
            });
          } else if (res.response.status === 429) {
            setStatus("error");
            setGroups([]);
            setNotice({
              title: "Too many searches",
              body: (
                <>
                  <p>Wait a moment, then retry.</p>
                  {traceEl}
                </>
              ),
            });
          } else {
            setStatus("error");
            setGroups([]);
            setNotice({
              title: "The search failed",
              body: (
                <>
                  <p>
                    The server could not answer. Retry; if it keeps failing, quote the trace ID to
                    your administrator.
                  </p>
                  {traceEl}
                </>
              ),
            });
          }
          return;
        }

        // Success 200
        const data = res.data;
        if (data) {
          setAsOf(data.asOf);
          const built = buildPaletteGroups(data, registeredPalette, routes, trimmed);
          setGroups(built);
          setStatus("results");
          if (built.length === 0) {
            setNotice({
              title: `No objects match “${trimmed}” in your scope`,
              body: (
                <p>
                  If you expected a result, your scope may not cover it: ask activeDIQ
                  administrators.
                </p>
              ),
            });
          }
        }
      } catch {
        if (requestIdRef.current !== reqId) return;
        setStatus("error");
        setGroups([]);
        setNotice({
          title: "Can't reach the server",
          body: <p>Check your connection, then retry.</p>,
        });
      }
    }, SEARCH_DEBOUNCE_MS);

    return () => clearTimeout(timer);
  }, [paletteOpen, query, client, registeredPalette, routes, retryCount]);

  const handleRetry = useCallback(() => {
    setRetryCount((c) => c + 1);
  }, []);

  const handleSelect = useCallback(
    (item: PaletteItem) => {
      setPaletteOpen(false);
      // Page from registered palette entries
      if (item.id.startsWith("page:")) {
        const entryId = item.id.slice("page:".length);
        const entry = registeredPalette.find((p) => p.id === entryId);
        if (entry) navigate(entry.route);
        return;
      }
      // User hit (exact or users group) -> /directory/users?q=
      if (item.typeTag === "User") {
        const target = item.identifier?.split(" · ")[0] || item.name;
        navigate(`/directory/users?q=${encodeURIComponent(target)}`);
        return;
      }
      // Group, Computer, Contact -> /search?q=
      const target = item.identifier?.split(" · ")[0] || item.name;
      navigate(`/search?q=${encodeURIComponent(target)}`);
    },
    [registeredPalette],
  );

  const handleShowAll = useCallback(
    (group: PaletteGroup) => {
      setPaletteOpen(false);
      const trimmed = query.trim();
      if (group.id === "exact") {
        navigate(`/search?q=${encodeURIComponent(trimmed)}`);
      } else {
        navigate(`/search?q=${encodeURIComponent(trimmed)}&type=${encodeURIComponent(group.id)}`);
      }
    },
    [query],
  );

  if (session === "checking") {
    return (
      <main className="diq-page">
        <Skeleton label="Checking your session" />
      </main>
    );
  }
  if (session === "unreachable") {
    return (
      <main className="diq-page">
        <StatePanel tone="error" title="Can't reach the server">
          <p>Check your connection, then retry.</p>
          <Button variant="primary" onClick={check}>
            Retry
          </Button>
        </StatePanel>
      </main>
    );
  }
  if (session === "none") {
    return (
      <SignInPage
        client={client}
        onSignedIn={() => {
          const next = safeNext(new URLSearchParams(window.location.search).get("next"), HOME_PATH);
          window.history.pushState(null, "", next);
          setPath(currentPath());
          setSession("active");
        }}
      />
    );
  }

  if (path === SIGN_IN_PATH) return null; // signed in already: the effect above moves on
  if (routes.length === 0) return null;
  const route = matchRoute(routes, path === "/" ? HOME_PATH : path);

  const footer = asOf ? (
    <span className="diq-hint">index as of {formatTime(asOf)}</span>
  ) : undefined;

  return (
    <div className="diq-shell">
      <header className="diq-shell__header" role="banner">
        <div className="diq-shell__brand">
          <span className="diq-wordmark">
            <span className="diq-wordmark-a">active</span>
            <span className="diq-wordmark-b">DIQ</span>
          </span>
        </div>
        <button
          type="button"
          className="diq-shell__search"
          data-testid="top-bar-search"
          aria-label="Search"
          onClick={openPalette}
        >
          <span className="diq-shell__search-placeholder">
            Search people, groups, computers, reports and actions
          </span>
          <span className="diq-shell__search-kbd">
            <Kbd>Ctrl</Kbd> <Kbd>K</Kbd>
          </span>
        </button>
      </header>

      <main className="diq-shell__content">
        {!route ? (
          <div style={{ padding: "var(--diq-space-5)" }}>
            <h1>Page not found</h1>
            <p>
              <a href="/directory/users">Go to Users</a>
            </p>
          </div>
        ) : (
          <route.component />
        )}
      </main>

      <CommandPalette
        open={paletteOpen}
        onClose={closePalette}
        query={query}
        onQueryChange={handleQueryChange}
        status={status}
        groups={groups}
        onSelect={handleSelect}
        onShowAll={handleShowAll}
        onRetry={handleRetry}
        {...(notice ? { notice } : {})}
        {...(footer ? { footer } : {})}
      />
    </div>
  );
}
