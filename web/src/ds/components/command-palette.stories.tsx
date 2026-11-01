import type { Meta, StoryObj } from "@storybook/react-vite";
import { useEffect, useState } from "react";

import "./components.css";
import {
  Button,
  CommandPalette,
  type PaletteGroup,
  type PaletteItem,
  type PaletteStatus,
  usePaletteShortcut,
} from "./index";

/** Fixture data: invented people on a reserved test domain. Real screens pass what the search API returns. */
const meta: Meta = { title: "Design system/Command palette", parameters: { layout: "fullscreen" } };
export default meta;
type Story = StoryObj;

const priya: PaletteItem = {
  id: "u1",
  typeTag: "User",
  name: "Priya Raman",
  identifier: "praman · priya.raman@corp.example.test",
  chips: [{ tone: "warn", label: "Locked 09:12" }],
  disambiguator: "Service desk lead · London",
  dn: "CN=Priya Raman,OU=Service Desk,OU=London,OU=Staff,DC=corp,DC=example,DC=test",
  domain: "corp.example.test",
  expandable: true,
};
const priya2: PaletteItem = {
  id: "u2",
  typeTag: "User",
  name: "Priya Raman",
  identifier: "praman2 · p.raman@corp.example.test",
  chips: [
    { tone: "muted", label: "Disabled" },
    { tone: "warn", label: "Password expires in 3 d" },
  ],
  disambiguator: "Finance analyst · Leeds",
  dn: "CN=Priya Raman,OU=Finance,OU=Leeds,OU=Staff,DC=corp,DC=example,DC=test",
  domain: "corp.example.test",
  expandable: true,
};
const priya3: PaletteItem = {
  id: "u3",
  typeTag: "User",
  name: "Priya Raman",
  identifier: "praman3 · priya.raman@emea.example.test",
  chips: [
    { tone: "crit", label: "Deleted 1 Oct 16:42" },
    { tone: "muted", label: "limited details" },
  ],
  disambiguator: "Former contractor",
  dn: "CN=Priya Raman\\0ADEL:6c0b0d9e-0000-4000-8000-000000000001,CN=Deleted Objects,DC=emea,DC=example,DC=test",
  domain: "emea.example.test",
};
const exact: PaletteItem = {
  id: "x1",
  typeTag: "User",
  name: "Raman, Priya (exact)",
  identifier: "praman",
  chips: [{ tone: "ok", label: "Enabled" }],
  dn: "CN=Priya Raman,OU=Service Desk,OU=London,OU=Staff,DC=corp,DC=example,DC=test",
};
const group: PaletteItem = {
  id: "g1",
  typeTag: "Group",
  name: "Raman Reviewers",
  identifier: "GG-Raman-Reviewers",
  chips: [{ tone: "crit", label: "TIER 0" }],
  disambiguator: "Security group · 14 members",
  dn: "CN=GG-Raman-Reviewers,OU=Groups,OU=Staff,DC=corp,DC=example,DC=test",
};
const computer: PaletteItem = {
  id: "c1",
  typeTag: "Computer",
  name: "LDN-RAMAN-01",
  identifier: "LDN-RAMAN-01$ · ldn-raman-01.corp.example.test",
  disambiguator: "Windows 11 · London",
  dn: "CN=LDN-RAMAN-01,OU=Workstations,OU=London,DC=corp,DC=example,DC=test",
};
const blocked: PaletteItem = {
  id: "a1",
  typeTag: "Action",
  name: "Reset password for Priya Raman",
  disabled: true,
  disabledReason: "Blocked: Priya Raman is a Tier 0 account. Needs the Tier 0 Admin role.",
};
const page: PaletteItem = { id: "p1", typeTag: "Page", name: "Locked-out users report" };

const RESULTS: PaletteGroup[] = [
  { id: "exact", label: "Exact", items: [exact] },
  { id: "users", label: "Users", items: [priya, priya2, priya3], total: 12 },
  { id: "groups", label: "Groups", items: [group] },
  { id: "computers", label: "Computers", items: [computer] },
  { id: "actions", label: "Actions", items: [blocked, page] },
];
const RECENT: PaletteGroup[] = [
  { id: "recent", label: "Recent", items: [priya, group] },
  {
    id: "pinned",
    label: "Pinned views",
    items: [{ id: "v1", typeTag: "View", name: "Disabled accounts in London" }],
  },
  { id: "suggested", label: "Suggested for this page", items: [page] },
];

function Demo(props: {
  readonly status: PaletteStatus;
  readonly groups: PaletteGroup[];
  readonly query?: string;
  readonly footer?: string;
  readonly onExpand?: boolean;
  readonly dir?: "rtl";
}) {
  const [open, setOpen] = useState(true);
  const [query, setQuery] = useState(props.query ?? "");
  usePaletteShortcut(() => setOpen(true), !open);
  useEffect(() => {
    if (props.dir) document.documentElement.dir = props.dir;
    return () => {
      document.documentElement.dir = "ltr";
    };
  }, [props.dir]);
  return (
    <div style={{ padding: "var(--diq-space-5)", minHeight: "100vh" }}>
      <Button onClick={() => setOpen(true)}>
        Search <kbd className="diq-kbd">Ctrl K</kbd>
      </Button>
      <CommandPalette
        open={open}
        onClose={() => setOpen(false)}
        query={query}
        onQueryChange={setQuery}
        status={props.status}
        groups={props.groups}
        onSelect={() => setOpen(false)}
        onShowAll={() => setOpen(false)}
        onRetry={() => undefined}
        {...(props.onExpand === false ? {} : { onExpand: () => undefined })}
        {...(props.footer ? { footer: props.footer } : {})}
      />
    </div>
  );
}

export const Idle: Story = {
  name: "Idle: empty query with recent items",
  render: () => <Demo status="idle" groups={RECENT} footer="index as of 1 min ago" />,
};
export const Loading: Story = {
  render: () => <Demo status="loading" groups={[]} query="raman" />,
};
export const GroupedResults: Story = {
  render: () => (
    <Demo status="results" groups={RESULTS} query="raman" footer="index as of 1 min ago" />
  ),
};
export const NoResults: Story = {
  render: () => (
    <Demo status="results" groups={[]} query="kowalski" footer="index as of 1 min ago" />
  ),
};
export const ErrorState: Story = {
  name: "Error",
  render: () => <Demo status="error" groups={[]} query="raman" />,
};
export const PermissionDenied: Story = {
  render: () => <Demo status="denied" groups={[]} />,
};
export const StaleIndexFooter: Story = {
  render: () => (
    <Demo
      status="results"
      groups={RESULTS}
      query="raman"
      footer="⚠ Index as of 47 min ago: results may be out of date"
    />
  ),
};

const LONG = "W".repeat(200);
export const LongAndHostileContent: Story = {
  name: "Long names, hostile markup, deep DNs",
  render: () => (
    <Demo
      status="results"
      query="img"
      groups={[
        {
          id: "users",
          label: "Users",
          items: [
            {
              id: "l1",
              typeTag: "User",
              name: LONG,
              identifier: LONG.toLowerCase(),
              chips: [{ tone: "warn", label: "Password expires in 3 d: " + "x".repeat(60) }],
              disambiguator: "Head of " + "Operations ".repeat(12),
              dn: "CN=WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,OU=Deeper,DC=corp,DC=example,DC=test",
              domain: "very-long-subdomain.emea.corp.example.test",
            },
            {
              id: "l2",
              typeTag: "User",
              name: `<img src=x onerror="alert(1)"> <script>alert(2)</script>`,
              identifier: `<b>bold</b> · "quoted" & 'single'`,
              dn: `CN=<img src=x>,OU=a&b,DC=corp,DC=example,DC=test`,
            },
            {
              id: "l3",
              typeTag: "User",
              name: "محمد الراشد",
              identifier: "malrashid · m.alrashid@corp.example.test",
              disambiguator: "قسم المالية",
              dn: "CN=محمد الراشد,OU=المالية,DC=corp,DC=example,DC=test",
            },
          ],
        },
      ]}
    />
  ),
};
export const RightToLeft: Story = {
  name: "Right to left",
  render: () => <Demo status="results" groups={RESULTS} query="raman" dir="rtl" />,
};
