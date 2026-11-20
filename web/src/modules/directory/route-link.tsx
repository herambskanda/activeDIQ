import type { MouseEvent, ReactNode } from "react";

import { navigate } from "../../app/location";

/**
 * A link that moves inside the console without a page load; a modified click or a new-tab click
 * behaves as a link. `to` must be a path on this console. A design-system router Link replaces this
 * (T-1076), and the reports module's copy with it.
 */
export function RouteLink({ to, children }: { readonly to: string; readonly children: ReactNode }) {
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return;
    }
    e.preventDefault();
    navigate(to);
  };
  if (!to.startsWith("/") || to.startsWith("//")) return <span>{children}</span>;
  return (
    // eslint-disable-next-line safe-primitives/safe-url-attributes -- a console path built by this module from its own constants and URLSearchParams, checked above; replaced by the DS router Link (T-1076)
    <a href={to} onClick={onClick}>
      {children}
    </a>
  );
}
