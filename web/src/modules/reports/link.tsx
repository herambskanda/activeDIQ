import type { MouseEvent, ReactNode } from "react";

import { navigate } from "../../app/location";

/** A link that moves inside the console without a page load; a modified click or a new-tab click behaves as a link. */
export function Link({
  to,
  children,
  className,
}: {
  readonly to: string;
  readonly children: ReactNode;
  readonly className?: string;
}) {
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return;
    }
    e.preventDefault();
    navigate(to);
  };
  // `to` is built by this module from encodeURIComponent'd IDs under /reports; anything else is refused.
  if (!to.startsWith("/") || to.startsWith("//")) return <span>{children}</span>;
  return (
    // eslint-disable-next-line safe-primitives/safe-url-attributes -- a console path checked above, not a user-editable URL; a DS router Link replaces this (follow-up ticket)
    <a href={to} onClick={onClick} {...(className ? { className } : {})}>
      {children}
    </a>
  );
}
