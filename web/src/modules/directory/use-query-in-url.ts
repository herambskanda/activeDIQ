import { useCallback, useEffect, useState } from "react";

const PARAM = "q";

function readQuery(): string {
  return new URLSearchParams(window.location.search).get(PARAM) ?? "";
}

/**
 * The search text, kept in the address bar as `?q=` so a search can be bookmarked, shared and
 * stepped through with back and forward. `commit` records a new query as a history entry;
 * navigating back or forward changes the text through the returned `text`.
 */
export function useQueryInUrl(): {
  text: string;
  setText: (text: string) => void;
  committed: string;
  commit: (text: string) => void;
} {
  const [text, setText] = useState(readQuery);
  const [committed, setCommitted] = useState(readQuery);

  useEffect(() => {
    const onPop = () => {
      const q = readQuery();
      setText(q);
      setCommitted(q);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const commit = useCallback((next: string) => {
    setCommitted(next);
    if (readQuery() === next) return;
    const url = new URL(window.location.href);
    if (next === "") url.searchParams.delete(PARAM);
    else url.searchParams.set(PARAM, next);
    window.history.pushState(null, "", url);
  }, []);

  return { text, setText, committed, commit };
}
