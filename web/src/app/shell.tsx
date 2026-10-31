import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import { Skeleton, StatePanel, Button } from "../ds/components";
import { collectRoutes, matchRoute, type WebModule } from "./modules";
import { loadSession, SIGN_IN_PATH, type SessionClient, safeNext } from "./session";
import { SignInPage } from "./sign-in";

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
 */
export function Shell({
  modules,
  client = api,
}: {
  readonly modules: readonly WebModule[];
  readonly client?: SessionClient;
}) {
  const routes = collectRoutes(modules);
  const [path, setPath] = useState(currentPath);
  const [session, setSession] = useState<Session>("checking");

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
  if (!route) {
    return (
      <main style={{ padding: "var(--diq-space-5)" }}>
        <h1>Page not found</h1>
        <p>
          <a href="/directory/users">Go to Users</a>
        </p>
      </main>
    );
  }
  return <route.component />;
}
