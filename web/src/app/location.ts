// In-console navigation. The shell and the screens read the address bar; `navigate` changes it and
// tells them, so a screen can move to another route (or change its own address-bar state) without a
// page load, and back and forward keep working.
import { useSyncExternalStore } from "react";

/** Moves to `to` (a path on this console, with an optional query). `replace` rewrites the current history entry. */
export function navigate(to: string, options: { readonly replace?: boolean } = {}): void {
  const current = window.location.pathname + window.location.search;
  if (to === current) return;
  if (options.replace) window.history.replaceState(null, "", to);
  else window.history.pushState(null, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("popstate", onChange);
  return () => window.removeEventListener("popstate", onChange);
}

const snapshot = () => window.location.pathname + window.location.search;

/** The current path and query, re-read on every navigation, back and forward. */
export function useLocation(): { readonly pathname: string; readonly search: URLSearchParams } {
  const full = useSyncExternalStore(subscribe, snapshot);
  const at = full.indexOf("?");
  return {
    pathname: at < 0 ? full : full.slice(0, at),
    search: new URLSearchParams(at < 0 ? "" : full.slice(at)),
  };
}
