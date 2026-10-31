import type { ReactNode } from "react";

/** A keyboard-shortcut hint, e.g. `Export <Kbd>E</Kbd>`. A hint only: the shortcut must also work from the control. */
export function Kbd({ children }: { readonly children: ReactNode }) {
  return <kbd className="diq-kbd">{children}</kbd>;
}
