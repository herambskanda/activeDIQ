import type { MouseEvent, ReactNode } from "react";

import { navigate } from "../../app/location";

export interface LinkProps {
  /** A path on this console, such as `/reports/abc`. Anything else (another origin, `//host`, a scheme) renders as plain text. */
  readonly to: string;
  readonly children: ReactNode;
  readonly className?: string;
}

/**
 * A link that moves inside the console without a page load. A modified click, a middle click and
 * "open in new tab" behave as for any link because the element is a real anchor with an href.
 * Only console paths are accepted: `to` must start with a single `/`, so it can never carry a
 * `javascript:` or other-origin URL. Not for leaving the console (use a plain anchor with a reviewed URL).
 */
export function Link({ to, children, className }: LinkProps) {
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return;
    }
    e.preventDefault();
    navigate(to);
  };
  if (!to.startsWith("/") || to.startsWith("//") || to.includes("\\")) {
    return <span className={className}>{children}</span>;
  }
  return (
    // eslint-disable-next-line safe-primitives/safe-url-attributes -- the one place a console path becomes an href: checked above to be a same-origin absolute path
    <a href={to} onClick={onClick} {...(className ? { className } : {})}>
      {children}
    </a>
  );
}
