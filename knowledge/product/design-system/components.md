---
title: Design-system components
status: draft
owner: component-designer
---

# Components (`web/src/ds/components`)

Import from `../../ds/components`. Tokens only; one component per concept.

| Component | Use for | Not for | Props |
| --- | --- | --- | --- |
| `Button` | Any action. `variant="primary"` for the one main action in a region | Navigation (use a link) | `variant`, `loading` (stays focusable, `aria-busy`, ignores clicks), native button props; `type` defaults to `button` |
| `TextInput` | A labelled text field with validation | Unlabelled inputs; the label is always visible | `label`, `error` (sets `aria-invalid`, linked by `aria-describedby`), `inputRef`, `trailing` (e.g. Clear), native input props |
| `Chip` | Short status, always with text | Colour-only signals | `tone: "ok" \| "muted"` |
| `Table` | Short read-only tables (tens of rows): sticky header, row-header column, cells truncate with full text in `title` | Anything long, sortable, selectable or resizable: use `DataGrid` | `caption`, `columns` (`key`, `header`, `rowHeader`, `mono`, `wrap`, `cell`, `title`), `rows`, `rowKey`. `wrap` lets one prose column (reasons, details) wrap instead of truncate |
| `DataGrid` | Result sets, directory lists, schedules: thousands of rows, server-driven sort, selection, resizable columns. See below | Short static lists (use `Table`); cells that need wrapping or variable height | `caption`, `columns`, `rows`, `rowKey`, `sort`/`onSort`, `selected`/`onSelectedChange`, `onRowActivate`, `resizable`/`onColumnResize`, `visibleRows`, `busy`, `empty` |
| `PopoverMenu` | A short list of actions from a button (export format, row actions), each optionally with an accelerator key. See below | Navigation (use links); settings that stay open (use `Popover`); more than about eight items | `label`, `trigger`, `items` (`id`, `label`, `description`, `accelerator`, `disabled`, `onSelect`), `header`, `footer`, `align`, `open`/`onOpenChange` |
| `Popover` | A few controls that apply as you change them (column chooser, domain scope), anchored to a button | Choosing one action (use `PopoverMenu`); anything with Save/Cancel (use `SideSheet`) | `label`, `trigger`, `children`, `align`, `open`/`onOpenChange` |
| `SideSheet` | Work that needs room and a Save: schedule, create, run details. Modal | A quick choice or a yes/no (menu or confirmation); non-modal detail | `open`, `onClose`, `title`, `description`, `width` (`default` 520 px, `wide` 760 px), `closeLabel`, `children` |
| `Toast` + `ToastRegion` | A short message about something that just happened, with at most one action ("Undo", "Run details") | Errors or anything the admin must act on (banner, `StatePanel`); progress | `Toast`: `tone` (`info`, `ok`), `action` (`label`, `onAction`), `onDismiss`, `dismissLabel`. `ToastRegion`: mount once per screen |
| `Skeleton` | Loading placeholder for lists | Spinners for short actions | `rows`, `label` (announced as status) |
| `StatePanel` | Empty and error blocks; `tone="error"` is `role=alert` | Inline field errors (use `TextInput error`) | `tone`, `title` |

States: hover, active, focus-visible (global ring), disabled, loading (Button), error (TextInput), read-only (TextInput) are all in `components.css`.
Reduced motion: transition and pulse durations collapse via the token and `base.css` rules.
Stories: `src/ds/components/data-grid.stories.tsx` (Storybook, `npm run storybook`; the a11y addon runs axe on every story). Other components still have their fixtures in `components.test.tsx` and the screen's Playwright suite.

## DataGrid (T-0952)

One data grid for the results grid, library and schedules list. ARIA `grid` on a real `<table>`; rows are one line high (`--diq-row`, so compact/comfortable density follows `<html data-density>`).

- **Virtualised.** Only the rows in view plus 3 either side are in the DOM (about 22 for 12,000, 18 at the top); spacer rows keep the scroll height. Rows must have a stable `rowKey`. Do not put wrapping or variable-height content in a cell.
- **Sorting is the caller's.** `sortable` columns show `aria-sort`; click, Enter or Space on the header calls `onSort(key)` once. The caller owns the order (the server sorts) and passes `sort`. Sort changes are announced politely ("Sorted by Name, ascending").
- **Sizing.** `width` is in characters (`ch`, default 16). `resizable` adds a pointer drag handle and Shift+Left/Right on a focused header (step 2 ch, 6 to 120 ch); `onColumnResize` lets the screen persist widths. The grid is as wide as its columns; spare room stays empty.
- **Row header.** The first column is the row header (`th scope=row`) and, with the selection column, stays in view when scrolling sideways. Put the name there.
- **Truncation.** Cells truncate with an ellipsis and carry the full text in `title`: automatic for string and number cells, pass `title` when the cell renders a component.
- **Selection.** On when `onSelectedChange` is given; `selected` is a set of row keys. Click the checkbox cell, Space on a row, Shift+click or Shift+Space for a range, Ctrl+A for all rows loaded, header checkbox for all (indeterminate when partial). Selection is of loaded rows: server-wide "select all 12,431" is the screen's banner, not the grid's.
- **Keyboard.** One tab stop. Arrows move between cells (mirrored in RTL), Home/End row ends, Ctrl+Home/Ctrl+End grid corners, PageUp/PageDown a page. Enter on a cell with a link or button moves into it (Tab reaches widgets only from their own cell; Escape returns to the cell); Enter on a plain cell calls `onRowActivate`.
- **States.** `busy` (`aria-busy`, progress cursor, signal rule under the header; never dimmed, so contrast holds), `empty` slot, focus ring inset on the cell, hover and selected row backgrounds on tokens that are in the contrast test. Dark and light both.
- **Not yet:** column reorder and hide (the screen's Columns popover owns visible columns today), group rows, inline editing, server paging (B12a: pass `rows` as they load).

## Overlays (T-0953)

Popover, PopoverMenu, SideSheet and Toast replace the reports prototype's local menu, sheet and toast CSS. Stories: `src/ds/components/overlays.stories.tsx`; interaction and axe tests: `overlays.test.tsx`.

- **Trigger.** `trigger={(p) => <Button {...p}>Export</Button>}`. Spread `p` on a `<button>`: it carries the ref (focus returns there), `aria-haspopup`, `aria-expanded`, `aria-controls`, the click toggle and, for a menu, Arrow Down/Up to open. To react to the click too (analytics), wrap `p.onClick` rather than replacing it. Open state is uncontrolled by default; pass `open`/`onOpenChange` when a screen coordinates several popovers or opens one from a shortcut key.
- **PopoverMenu keys.** Focus goes to the first available item on open. Arrow Up/Down move (wrapping), Home/End jump, Enter/Space/click invoke. An item's one-character `accelerator` invokes it from anywhere in the open menu (case-insensitive; ignored with Ctrl, Alt or Meta). That is why there is no type-ahead. Choosing closes the menu and puts focus back on the trigger **before** `onSelect` runs, so a sheet the item opens restores focus to the trigger in turn. Escape and Tab close it too (Tab parks focus on the trigger). A press outside, or focus moving away, closes it and leaves focus where the user put it.
- **Disabled items** are `aria-disabled`: still focusable and readable, never invoked (not by click or accelerator), menu stays open. Say why in `description` ("limit 100,000 rows"); give a longer explanation a `role="alert"` of its own in `footer`.
- **Popover** is a non-modal `role="dialog"` named by `label`. First control takes focus (mark another with `data-autofocus`). Same close rules as the menu.
- **Placement.** Panels open below the trigger, lined up with its start or end edge (`align`), mirrored in RTL. They are not portalled and do not flip at the viewport edge: put end-aligned triggers on the right side of a toolbar. They stay inside a SideSheet's focus trap.
- **SideSheet.** Modal, from the inline-end edge. While open: focus is trapped (Tab and Shift+Tab wrap; stray focus is pulled back), everything else on `body` is `inert` (a `ToastRegion` is exempt so announcements still arrive), Escape, the Close button and a click on the scrim (press and release both on it, so a drag from inside never closes) call `onClose` (the caller may confirm unsaved work), and on close focus returns to the element that had it when the sheet opened. Initial focus: an `autoFocus` or `data-autofocus` control, else the first tabbable (Close). Children own their layout; put the `<form>` and its submit button inside. It leaves instantly (no exit animation). The slide-in uses `--diq-dur`, which is 0 under reduced motion.
- **Toast.** Lives in a `ToastRegion` (`role="status"`, `aria-live="polite"`), a persistent region on `body`, so a toast that arrives later is announced politely without taking focus. Mount the region once per screen and render at most one `Toast` in it. Nothing times out (WCAG 2.2.1); it stays until dismissed or replaced. The action calls `onAction` once and then `onDismiss`; if the toast held focus when it unmounts, focus returns to where the keyboard user came from, not the page. While a SideSheet is open the toast action is outside the focus trap: raise toasts that need the action after the sheet closes.
- **Tokens.** New with this ticket: `--diq-z-popover`, `--diq-z-sheet`, `--diq-z-toast` (layers), `--diq-scrim` (the existing prototype value, 35 % black, both themes), `--diq-sheet-w-wide`, `--diq-popover-w`, `--diq-toast-w`.
- **Not yet:** flipping/portalled popovers, nested submenus, checkbox and radio menu items, multiple stacked toasts, an exit animation.
