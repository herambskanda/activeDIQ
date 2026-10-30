import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type Ref,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";

/** What the trigger element must spread so the popover can open, close and return focus to it. */
export interface PopoverTriggerProps {
  readonly ref: Ref<HTMLButtonElement>;
  readonly "aria-haspopup": "menu" | "dialog";
  readonly "aria-expanded": boolean;
  readonly "aria-controls": string | undefined;
  readonly onClick: () => void;
  readonly onKeyDown: (e: ReactKeyboardEvent<HTMLElement>) => void;
}

interface OpenProps {
  /** Controlled open state. Omit it (and use `defaultOpen`) to let the popover keep its own. */
  readonly open?: boolean;
  readonly defaultOpen?: boolean;
  readonly onOpenChange?: (open: boolean) => void;
}

interface CommonProps extends OpenProps {
  /** Renders the trigger: `trigger={(p) => <Button {...p}>Export</Button>}`. */
  readonly trigger: (props: PopoverTriggerProps) => ReactNode;
  /** Which edge of the trigger the panel lines up with (logical, so it mirrors in RTL). */
  readonly align?: "start" | "end";
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function tabbables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.closest("[inert], [hidden]"),
  );
}

interface ShellProps extends CommonProps {
  readonly kind: "menu" | "dialog";
  readonly label: string;
  readonly className?: string;
  /** Called with the panel after it opens; return the element that takes focus. */
  readonly initialFocus: (panel: HTMLElement) => HTMLElement | null;
  /** Panel-level key handling (menu navigation); `close` returns focus to the trigger. */
  readonly onPanelKeyDown?: (
    e: ReactKeyboardEvent<HTMLElement>,
    panel: HTMLElement,
    close: PopoverClose,
  ) => void;
  readonly children: ReactNode | ((close: PopoverClose) => ReactNode);
}

/** Closes the popover; `true` (the default) returns focus to the trigger first. */
type PopoverClose = (restoreFocus?: boolean) => void;

/**
 * The anchored, non-modal panel under a trigger. Shared by `Popover` (a form or details panel,
 * role=dialog) and `PopoverMenu` (role=menu). Closes on Escape (focus returns to the trigger), on a
 * pointer press outside and when focus leaves; the last two leave focus where the user put it.
 * It is not portalled, so it stays inside a SideSheet's focus trap; it does not flip at the
 * viewport edge, so place it with `align` where the trigger leaves room.
 */
function PopoverShell(props: ShellProps) {
  const { kind, label, trigger, align = "start", className, initialFocus, onPanelKeyDown } = props;
  const [inner, setInner] = useState(props.defaultOpen ?? false);
  const isOpen = props.open ?? inner;
  const controlled = props.open !== undefined;
  const { onOpenChange } = props;
  const wrap = useRef<HTMLSpanElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const triggerEl = useRef<HTMLButtonElement | null>(null);
  const panelId = useId();

  const setOpen = useCallback(
    (v: boolean) => {
      if (!controlled) setInner(v);
      onOpenChange?.(v);
    },
    [controlled, onOpenChange],
  );
  const close = useCallback<PopoverClose>(
    (restoreFocus = true) => {
      setOpen(false);
      if (restoreFocus) triggerEl.current?.focus();
    },
    [setOpen],
  );

  useEffect(() => {
    if (!isOpen) return;
    const p = panel.current;
    if (p && !p.contains(document.activeElement)) (initialFocus(p) ?? p).focus();
    const away = (e: PointerEvent) => {
      if (wrap.current && !wrap.current.contains(e.target as Node)) close(false);
    };
    document.addEventListener("pointerdown", away);
    return () => document.removeEventListener("pointerdown", away);
    // initialFocus is read once per opening; a new function identity must not steal focus again.
  }, [isOpen, close]);

  const triggerProps: PopoverTriggerProps = {
    ref: (el) => {
      triggerEl.current = el;
    },
    "aria-haspopup": kind,
    "aria-expanded": isOpen,
    "aria-controls": isOpen ? panelId : undefined,
    onClick: () => setOpen(!isOpen),
    onKeyDown: (e) => {
      if (kind === "menu" && !isOpen && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
        e.preventDefault();
        setOpen(true);
      }
    },
  };

  return (
    <span
      ref={wrap}
      className="diq-pop"
      onKeyDown={(e) => {
        if (!isOpen || e.nativeEvent.isComposing) return;
        if (e.key === "Escape") {
          // The popover owns this Escape: a SideSheet around it must stay open.
          e.stopPropagation();
          close(true);
        }
      }}
      onBlur={(e) => {
        const next = e.relatedTarget;
        if (isOpen && next instanceof Node && !wrap.current?.contains(next)) close(false);
      }}
    >
      {trigger(triggerProps)}
      {isOpen ? (
        <div
          ref={panel}
          id={panelId}
          tabIndex={-1}
          role={kind === "dialog" ? "dialog" : undefined}
          aria-label={kind === "dialog" ? label : undefined}
          className={`diq-pop__panel diq-pop__panel--${align}${className ? ` ${className}` : ""}`}
          onKeyDown={(e) => {
            if (!e.nativeEvent.isComposing && panel.current)
              onPanelKeyDown?.(e, panel.current, close);
          }}
        >
          {typeof props.children === "function" ? props.children(close) : props.children}
        </div>
      ) : null}
    </span>
  );
}

export interface PopoverProps extends CommonProps {
  /** The accessible name of the panel (a short noun: "Columns", "Domains"). */
  readonly label: string;
  readonly children: ReactNode;
}

/**
 * A small non-modal panel anchored to a button, for a few controls that apply as you change them
 * (column chooser, domain scope). First control takes focus; mark another with `data-autofocus`.
 * Not for choosing one action from a list (use `PopoverMenu`) or anything that needs Save/Cancel
 * (use `SideSheet`).
 */
export function Popover({ label, children, ...rest }: PopoverProps) {
  return (
    <PopoverShell
      {...rest}
      kind="dialog"
      label={label}
      className="diq-pop__panel--form"
      initialFocus={(p) =>
        p.querySelector<HTMLElement>("[data-autofocus]") ?? tabbables(p)[0] ?? null
      }
    >
      {children}
    </PopoverShell>
  );
}

export interface PopoverMenuItem {
  readonly id: string;
  readonly label: ReactNode;
  /** Secondary line: what the choice does, or why it is unavailable. */
  readonly description?: ReactNode;
  /** One character. Pressing it while the menu is open invokes the item (no Ctrl, Alt or Meta). */
  readonly accelerator?: string;
  /** Stays focusable and readable, but cannot be invoked: say why in `description`. */
  readonly disabled?: boolean;
  readonly onSelect: () => void;
}

export interface PopoverMenuProps extends CommonProps {
  /** The accessible name of the menu ("Export format"). */
  readonly label: string;
  readonly items: readonly PopoverMenuItem[];
  /** Context above the items (what will be affected). Not part of the menu semantics. */
  readonly header?: ReactNode;
  /** Notes below the items. Give an error a `role="alert"` of its own. */
  readonly footer?: ReactNode;
}

const itemsOf = (panel: HTMLElement) =>
  Array.from(panel.querySelectorAll<HTMLElement>('[role="menuitem"]'));
const enabled = (els: HTMLElement[]) =>
  els.filter((el) => el.getAttribute("aria-disabled") !== "true");

/**
 * A menu of actions with accelerator keys (WAI-ARIA menu button pattern). The trigger opens it with a
 * click or Arrow Down; focus goes to the first available item; Arrow keys, Home and End move;
 * an item's accelerator key invokes it; Enter or Space on the focused item invokes it; Tab, Escape
 * and a choice close it. After a choice or Escape, focus is back on the trigger *before* `onSelect`
 * runs, so a sheet that `onSelect` opens will restore focus to the trigger in turn.
 * No type-ahead: letters are accelerators. Not for navigation (use links) or for settings that
 * stay open (use `Popover`).
 */
export function PopoverMenu({ label, items, header, footer, ...rest }: PopoverMenuProps) {
  return (
    <PopoverShell
      {...rest}
      kind="menu"
      label={label}
      className="diq-pop__panel--menu"
      initialFocus={(p) => enabled(itemsOf(p))[0] ?? itemsOf(p)[0] ?? null}
      onPanelKeyDown={(e, p, close) => {
        const els = itemsOf(p);
        const at = els.indexOf(document.activeElement as HTMLElement);
        const go = (i: number) => {
          e.preventDefault();
          els[(i + els.length) % els.length]?.focus();
        };
        if (e.key === "ArrowDown") go(at + 1);
        else if (e.key === "ArrowUp") go(at < 0 ? els.length - 1 : at - 1);
        else if (e.key === "Home") go(0);
        else if (e.key === "End") go(els.length - 1);
        else if (e.key === "Tab") {
          // Tab leaves the menu: close it and park focus on the trigger, from where Tab moves on.
          e.preventDefault();
          close(true);
        } else if (e.key.length === 1 && e.key !== " " && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const hit = items.find((it) => it.accelerator?.toLowerCase() === e.key.toLowerCase());
          if (hit) {
            e.preventDefault();
            choose(hit, close);
          }
        }
      }}
    >
      {(close) => (
        <>
          {header ? <div className="diq-menu__note">{header}</div> : null}
          <div role="menu" aria-label={label} className="diq-menu">
            {items.map((it) => (
              <button
                key={it.id}
                type="button"
                role="menuitem"
                tabIndex={-1}
                className="diq-menu__item"
                aria-disabled={it.disabled || undefined}
                aria-keyshortcuts={it.accelerator?.toUpperCase()}
                onClick={() => choose(it, close)}
              >
                <span className="diq-menu__text">
                  <span className="diq-menu__label">{it.label}</span>
                  {it.description ? <span className="diq-menu__desc">{it.description}</span> : null}
                </span>
                {it.accelerator ? (
                  <kbd className="diq-menu__key" aria-hidden="true">
                    {it.accelerator.toUpperCase()}
                  </kbd>
                ) : null}
              </button>
            ))}
          </div>
          {footer}
        </>
      )}
    </PopoverShell>
  );
}

/** Every choice, by pointer, Enter, Space or accelerator, ends here: close, then run it. */
function choose(item: PopoverMenuItem, close: PopoverClose) {
  if (item.disabled) return;
  close(true);
  item.onSelect();
}
