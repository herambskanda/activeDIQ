# Worked decision requests

Two requests written to the bar in `SKILL.md`. Ticket IDs are illustrative. Copy the shape, not
the content: before filing either for real, check `decisions-log.md`. The CEO may already have
answered.

---

## 1. Directional — deployment model for v1

Why it is directional: category 4 (architecture fork with business impact). It decides who can
buy v1, what we must operate, and which ADRs can be written.

**Context file** (`/tmp/D-ctx.md`):

```markdown
**Question.** Where does activeDIQ v1 run: in the customer's network, in our cloud, or both?

**Why now.** The stack ADR, installer work and the first build tickets all depend on it.
Nothing past research can start until this is answered.

**What we know.** ManageEngine's AD tools are customer-hosted Windows software. ADSelfService
Plus has no vendor-hosted SaaS edition
([download page](https://www.manageengine.com/products/self-service-password/download.html)).
The customers we are displacing already run on-prem. Any cloud option needs an on-prem
connector to reach their domain controllers, because DCs are not exposed to the internet.

| | a. Self-hosted first | b. SaaS + on-prem connector | c. Both from day one |
| --- | --- | --- | --- |
| Buys | Like-for-like swap for ME customers; no hosting cost; fits air-gapped sites | Fast onboarding; we control upgrades; recurring revenue | Widest market |
| Costs | Customers run upgrades; slower feedback | We hold Tier-0 credentials, which brings a security and compliance burden; some buyers refuse | Two release trains; roughly 1.5× platform work before the first demo [UNVERIFIED estimate] |
| Reversibility | Adding SaaS later is feasible if the tenant key is in the first migration (we will do this either way) | Hard to add a strong self-hosted offering later | — |

**Blocks.** T-0004 (stack ADR), T-0005 (installer spike), T-0006 (M1 plan).
**Recommendation.** a. It matches how the target customers buy today, and keeps SaaS open.
```

**Command:**

```bash
factory/bin/factory decision new --kind directional --by factory-director \
  --title "Deployment model for v1" \
  --question "Where should activeDIQ v1 run?" \
  --context-file /tmp/D-ctx.md \
  --option "a|Self-hosted first|Runs in the customer's network; SaaS later on the same core" \
  --option "b|SaaS + connector|We host it; a small connector reaches their DCs" \
  --option "c|Both from day one|Two delivery models, two release trains" \
  --recommend a \
  --rationale "Matches how ManageEngine customers buy today; tenant key from day one keeps SaaS open." \
  --blocks T-0004,T-0005,T-0006
```

No preview, because there is no taste involved. No default, because the request is
directional.

---

## 2. Advisory — default density of directory tables

Why it is advisory: category 2 (taste). We have a sound default, and nothing irreversible waits
on the answer.

**Previews** in `factory/demos/previews/D-0009/`. The folder name was reserved as highest D-id + 1.

| File | Shows |
| --- | --- |
| `a.html` / `a.png` | Users table, 40 px rows, density toggle in the table toolbar |
| `b.html` / `b.png` | Same table, 32 px rows, no toggle |
| `c.html` / `c.png` | Same table, 40 px rows, no toggle |
| `index.md` | The three side by side, plus what changes between them |

Each HTML file shows the same 25 sample users and the same columns: name, sAMAccountName, OU,
last logon, enabled, locked. It links `/tokens.css`, keeps all other CSS and SVG inline, and
has "Preview — sample data" in the corner.

**Context file** (`/tmp/D-ctx.md`):

```markdown
**Question.** How dense should the user, group and computer tables be by default?

Admins spend most of their time in these tables. Denser rows show more objects at once but
are slower to scan. Previews: [a](factory/demos/previews/D-0009/a.html) ·
[b](factory/demos/previews/D-0009/b.html) · [c](factory/demos/previews/D-0009/c.html).

- **a. Comfortable, compact toggle.** 40 px rows; each admin can switch per table, and the
  choice is remembered. Costs one toolbar control.
- **b. Compact.** 32 px rows; about 25 % more rows on screen. Harder to scan and to hit on touch.
- **c. Comfortable only.** 40 px rows; simplest. Power users will ask for a denser view.

**Blocks.** T-0031 (table component), T-0032 (users screen). Other work continues.
**Reversibility.** Cheap. Density is a token-level setting, so changing it later is a one-line
change plus screenshot updates.
**Default.** a applies automatically 72 h after filing if there is no answer.
```

**Command:**

```bash
factory/bin/factory decision new --kind advisory --by product-designer \
  --title "Default density for directory tables" \
  --question "How dense should user, group and computer tables be by default?" \
  --context-file /tmp/D-ctx.md \
  --option "a|Comfortable, compact toggle|40 px rows; admins switch per table" \
  --option "b|Compact|32 px rows; more on screen, harder to scan" \
  --option "c|Comfortable only|40 px rows; simplest, no toggle" \
  --recommend a \
  --rationale "Readable by default, fast for power users; the toggle costs one control." \
  --default a --default-in 72h --blocks T-0031,T-0032
```

**After the answer**, during director triage: say the CEO picks b and adds the note "we're
building for people who live in these tables". Record "Prefers dense, power-user layouts over
spacious ones" in `ceo-preferences.md`. The next density or layout question then gets b-style
defaults without anyone asking again.
