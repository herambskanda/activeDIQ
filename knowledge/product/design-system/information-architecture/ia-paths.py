# Verifies T-0009 AC1: every top-20 task has a path from Home, built only from IA elements
# defined in information-architecture.md §9, within the T-0008 interaction budget and target time.
# Budgets are read from the T-0008 re-total script (klm.py), so the two cannot drift apart.
# Counting rules: knowledge/product/specs/top-admin-tasks-benchmark.md §1.2. Time model: §1.3.
# Run: python3 ia-paths.py        (exit code 1 if any path is over budget)
import ast, math, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
KLM = HERE.parents[1] / "specs" / "top-admin-tasks-benchmark-evidence" / "klm.py"

def budgets():
    tree = ast.parse(KLM.read_text())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and node.targets[0].id in ("us", "extra"):
            out.update(ast.literal_eval(node.value))
    return out

# IA element catalogue: element -> (I, F, S), costed by T-0008 §1.2. Section numbers refer to
# information-architecture.md. An element that is not in this catalogue fails the run.
E = {
    # Shell and navigation (§3)
    "rail.item":            (1, 0, 1),  # click a rail item (Users, Clean up, Settings…): route change
    "home.quick-action":    (1, 0, 1),  # Home quick action that opens a sheet (New user…)
    "rail.pinned-view":     (1, 0, 1),  # a pinned saved view in the rail or on Home
    "key.N":                (1, 0, 1),  # global shortcut: New user sheet
    # Search overlay (§5)
    "search.open":          (1, 0, 1),  # `/` or Ctrl/Cmd+K: the overlay is a pop-up, so 1 screen
    "search.type":          (1, 1, 0),
    "search.enter":         (1, 0, 1),  # opens the object page or report
    # Object page (§6)
    "page.action.sheet":    (1, 0, 1),  # single-key action or button that opens the one side sheet
    "page.action.inplace":  (1, 0, 0),  # action that completes in place (Unlock): toast, no screen
    "page.tab":             (1, 0, 0),  # in-page tab switch
    "page.expand":          (1, 0, 0),  # expand a panel in place
    "page.inline.open":     (1, 0, 0),  # click an inline-editable field
    "page.inline.type":     (1, 1, 0),
    "page.inline.commit":   (1, 0, 0),  # Enter
    "page.reveal":          (1, 0, 0),  # "Show recovery key / local admin password": inline chooser
    "page.reveal.reason":   (1, 0, 0),
    "stepup.code":          (1, 1, 1),  # inline step-up prompt (TM-D16); counted as a screen by §1.2
    "page.members.effective": (1, 0, 0),  # Direct / Effective toggle
    "page.export":          (1, 0, 0),
    "page.export.format":   (1, 0, 0),
    "page.filter.type":     (1, 1, 0),  # filter box inside a tab (History, Members)
    # Side sheet (§6.4)
    "sheet.typeahead.type": (1, 1, 0),
    "sheet.typeahead.pick": (1, 0, 0),
    "sheet.field.type":     (1, 1, 0),
    "sheet.option":         (1, 0, 0),  # toggle, preset, radio, list choice
    "sheet.paste":          (1, 0, 0),
    "sheet.send-code":      (1, 0, 0),  # caller verification (ENH-09)
    "sheet.code.type":      (1, 1, 0),
    "sheet.typed-confirm":  (1, 1, 0),  # type the count or the name (P6)
    "sheet.confirm":        (1, 0, 0),
    "sheet.to-page":        (1, 0, 1),  # sheet link that opens a full page (Import from a file)
    # Lists (§7)
    "table.filter.type":    (1, 1, 0),
    "table.filter.enter":   (1, 0, 0),
    "table.select-all":     (1, 0, 0),  # Ctrl+A = all matching, stated in words
    "table.bulk.sheet":     (1, 0, 1),
    "table.group.expand":   (1, 0, 0),
    "table.row.include":    (1, 0, 0),
    # Clean up (§4.3)
    "cleanup.card":         (1, 0, 1),
    # Import page (§7.3)
    "file.picker":          (2, 0, 1),  # OS file picker: open + choose, 1 screen (§1.2)
    "import.mapping.ok":    (1, 0, 0),
    "import.run":           (1, 0, 0),
    # Delegation (§8.6)
    "wizard.open":          (1, 0, 1),
    "wizard.typeahead.type": (1, 1, 0),
    "wizard.typeahead.pick": (1, 0, 0),
    "wizard.option":        (1, 0, 0),
    "wizard.confirm":       (1, 0, 0),
}

S, P = "search", "page"
SEARCH = ["search.open", "search.type", "search.enter"]
PATHS = {
    "T01": SEARCH + ["page.action.sheet", "sheet.send-code", "sheet.code.type", "sheet.confirm"],
    "T01b": SEARCH + ["page.action.sheet", "sheet.confirm"],               # without verification
    "T02": SEARCH + ["page.expand", "page.action.inplace"],
    "T03": SEARCH,
    "T04": SEARCH + ["page.reveal", "page.reveal.reason", "stepup.code"],
    "T04w": SEARCH + ["page.reveal", "page.reveal.reason"],               # inside step-up window
    "T05": SEARCH + ["page.reveal", "page.reveal.reason", "stepup.code"],
    "T06": SEARCH + ["page.action.sheet", "sheet.typeahead.type", "sheet.typeahead.pick", "sheet.confirm"],
    "T07": ["key.N", "sheet.field.type", "sheet.field.type", "sheet.typeahead.type", "sheet.typeahead.pick", "sheet.confirm"],
    "T08": ["key.N", "sheet.to-page", "file.picker", "import.mapping.ok", "import.run"],
    "T09": SEARCH + ["page.action.sheet", "sheet.confirm"],
    "T10": SEARCH + ["page.action.sheet", "sheet.field.type", "sheet.field.type", "sheet.typeahead.type",
                     "sheet.typeahead.pick", "sheet.typeahead.type", "sheet.typeahead.pick", "sheet.confirm"],
    "T11": SEARCH + ["page.action.sheet", "sheet.paste", "sheet.option", "sheet.option", "sheet.confirm"],
    "T12": ["rail.item", "table.filter.type", "table.filter.enter", "table.select-all", "table.bulk.sheet",
            "sheet.typeahead.type", "sheet.typeahead.pick", "sheet.field.type", "sheet.confirm"],
    "T13": SEARCH + ["page.inline.open", "page.inline.type", "page.inline.commit"],
    "T14": SEARCH + ["page.action.sheet", "sheet.option", "sheet.confirm"],
    "T15": SEARCH + ["page.action.sheet", "sheet.confirm"],
    "T16": SEARCH + ["page.tab", "page.filter.type"],
    "T17": ["rail.item", "cleanup.card", "table.select-all", "table.bulk.sheet", "sheet.option",
            "sheet.typed-confirm", "sheet.confirm",
            "rail.item", "cleanup.card", "sheet.typed-confirm", "sheet.confirm"],
    "T18": ["rail.item", "cleanup.card", "table.group.expand", "table.row.include", "table.select-all",
            "table.bulk.sheet", "sheet.option", "sheet.typed-confirm", "sheet.confirm",
            "rail.item", "cleanup.card", "sheet.typed-confirm", "sheet.confirm"],
    "T19": SEARCH + ["page.members.effective", "page.export", "page.export.format"],
    "T20": SEARCH + ["page.action.sheet", "sheet.option", "sheet.field.type", "sheet.confirm"],
}
# T17/T18 visit 2: the "Pending deletion · Review & approve" card opens a sheet over the Clean up
# page, so it is costed as cleanup.card (1 I, 1 S), matching T-0008's visit-2 rows.

# Robustness variants (§9.3). Each must also fit the same budget.
VARIANTS = {
    # Single-key shortcuts switched off (WCAG 2.1.4 setting): every key has a visible button that
    # costs the same, and N becomes the Home quick action "New user".
    "T07 shortcuts off": (["home.quick-action"] + PATHS["T07"][1:], "T07"),
    "T08 shortcuts off": (["home.quick-action"] + PATHS["T08"][1:], "T08"),
    # Clean up reached from Home's "Needs you" card instead of the rail: same cost.
    # Multi-domain forest: no domain selector anywhere (§3.4), so 0 extra steps (ME: +2).
}

# Delegation setup (§8.6). Not a top-20 task; compared with ME's documented OU-based delegation.
ME_D01 = [  # (step, I, F, S, tag) — https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/ou-based-delegation.html
    ("Delegation tab", 1, 0, 1, "doc"),
    ("Help Desk Delegation (sub-menu)", 1, 0, 0, "doc"),
    ("Help Desk Technician", 1, 0, 1, "doc"),
    ("Edit technician (row action)", 1, 0, 1, "doc"),
    ("OU-based Delegation; pop-up opens", 1, 0, 1, "doc"),
    ("Switch Now", 1, 0, 0, "doc"),
    ("Select domain (preselected in one domain, so 0)", 0, 0, 0, "doc"),
    ("Tick Select OUs", 1, 0, 0, "doc"),
    ("OU picker: open, expand, select, OK (T-0008 §1.2 standard)", 4, 0, 1, "inferred"),
    ("Choose the role under Help Desk Roles (drop-down)", 2, 0, 0, "doc; control type inferred"),
    ("Save Changes", 1, 0, 0, "doc"),
]
US_D01 = ["rail.item", "wizard.open", "wizard.typeahead.type", "wizard.typeahead.pick", "wizard.option",
          "wizard.typeahead.type", "wizard.typeahead.pick", "stepup.code", "wizard.confirm"]

def total(path):
    i = f = s = 0
    for el in path:
        if el not in E:
            sys.exit(f"unknown IA element: {el}")
        a, b, c = E[el]
        i, f, s = i + a, f + b, s + c
    return i, f, s

def t(i, f, s):
    return 1.3 * (i - f) + 3.2 * f + 1.35 * s

def target(i, f, s):
    return math.ceil(1.1 * (t(i, f, s) + s) - 1e-9)

def main():
    b = budgets()
    fails = 0
    print(f"{'task':<20}{'IA path I/F/S':<16}{'budget I/F/S':<16}{'T+W':>7}{'target':>8}  result")
    rows = [(k, p, k) for k, p in PATHS.items()] + [(k, p, ref) for k, (p, ref) in VARIANTS.items()]
    for name, path, ref in rows:
        got, bud = total(path), b[ref]
        ok = got[0] <= bud[0] and target(*got) <= target(*bud)
        fails += not ok
        print(f"{name:<20}{'/'.join(map(str, got)):<16}{'/'.join(map(str, bud)):<16}"
              f"{t(*got) + got[2]:>6.1f}s{target(*bud):>7}s  {'PASS' if ok else 'FAIL'}")
    tops = [total(PATHS[k]) for k in PATHS if len(k) == 3]
    ti, tf, ts = (sum(x[n] for x in tops) for n in range(3))
    print(f"\nTop-20 total (T01 with verification, T04/T05 outside the step-up window): "
          f"{ti}/{tf}/{ts}, T = {t(ti, tf, ts):.1f} s wait-free")
    me = tuple(sum(r[n] for r in ME_D01) for n in (1, 2, 3))
    us = total(US_D01)
    print(f"D01 delegate reset+unlock over one OU to a help-desk group: ME {me[0]}/{me[1]}/{me[2]} "
          f"T={t(*me):.1f} s | activeDIQ {us[0]}/{us[1]}/{us[2]} T={t(*us):.1f} s "
          f"({(t(*us) / t(*me) - 1) * 100:+.0f}%), target {target(*us)} s")
    print("ALL PASS" if not fails else f"{fails} FAIL")
    sys.exit(1 if fails else 0)

main()
