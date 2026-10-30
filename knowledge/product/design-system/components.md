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
| `Table` | Read-only data tables: sticky header, row-header column, cells truncate with full text in `title` | Selection, resize, virtualisation (not built yet: separate ticket) | `caption`, `columns` (`key`, `header`, `rowHeader`, `mono`, `cell`, `title`), `rows`, `rowKey` |
| `Skeleton` | Loading placeholder for lists | Spinners for short actions | `rows`, `label` (announced as status) |
| `StatePanel` | Empty and error blocks; `tone="error"` is `role=alert` | Inline field errors (use `TextInput error`) | `tone`, `title` |

States: hover, active, focus-visible (global ring), disabled, loading (Button), error (TextInput), read-only (TextInput) are all in `components.css`.
Reduced motion: transition and pulse durations collapse via the token and `base.css` rules.
Known gaps: no Storybook in the repo yet, so fixtures live in `components.test.tsx` and the screen's Playwright suite (axe, keyboard).
