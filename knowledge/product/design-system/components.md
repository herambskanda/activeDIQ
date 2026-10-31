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
