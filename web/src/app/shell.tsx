import { useEffect, useState } from "react";

import { collectRoutes, type WebModule } from "./modules";

/** Where the console opens when the address names no screen. */
const HOME_PATH = "/directory/users";

function currentPath(): string {
  return window.location.pathname.replace(/\/+$/, "") || "/";
}

/**
 * The console shell. It mounts the screen whose route matches the address, from the routes the
 * registered modules contribute. With no module it renders nothing; an address no route matches
 * says so rather than showing a blank page.
 */
export function Shell({ modules }: { readonly modules: readonly WebModule[] }) {
  const routes = collectRoutes(modules);
  const [path, setPath] = useState(currentPath);

  useEffect(() => {
    const onPop = () => setPath(currentPath());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  if (routes.length === 0) return null;
  const route = routes.find((r) => r.path === (path === "/" ? HOME_PATH : path));
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
