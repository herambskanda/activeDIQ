import type { Meta, StoryObj } from "@storybook/react-vite";

import { Reports } from "./Reports";

const meta = {
  title: "Prototype/Reports 2a",
  component: Reports,
  parameters: {
    docs: {
      description: {
        component:
          "Design prototype (T-0867). Every name, count, date and file name is SAMPLE data from fixtures.ts; no file is produced. The counter at the top counts interactions against the spec §5 budgets.",
      },
    },
  },
} satisfies Meta<typeof Reports>;
export default meta;
type Story = StoryObj<typeof meta>;

const NO_EXPORT = { run: true, exportFiles: false, schedule: false, external: false } as const;
const NO_EXTERNAL = { run: true, exportFiles: true, schedule: true, external: false } as const;

/** Start here: press / and try "domain admins nested" (T19) or "password never expires" (T20). */
export const EndToEnd: Story = {};

// ---- library ----
export const Library: Story = {};
export const LibraryFilteredByMeName: Story = {
  args: { initial: { libraryQuery: "recently logged" } },
};
export const LibraryNoMatch: Story = { args: { initial: { libraryQuery: "zzqx" } } };
export const NoReportsPermission: Story = {
  args: {
    perms: { run: false, exportFiles: false, schedule: false, external: false },
    initial: { forbidden: true },
  },
};
export const SearchNoPermission: Story = {
  args: {
    perms: { run: false, exportFiles: false, schedule: false, external: false },
    initial: { searchOpen: true, query: "inactive users" },
  },
};

// ---- search ----
export const SearchInactive: Story = {
  args: { initial: { searchOpen: true, query: "inactive users" } },
};
export const SearchMeName: Story = {
  args: { initial: { searchOpen: true, query: "Recently Logged on Users" } },
};
export const SearchNestedGroup: Story = {
  args: { initial: { searchOpen: true, query: "domain admins nested" } },
};
export const SearchNoMatch: Story = { args: { initial: { searchOpen: true, query: "zzqx" } } };

// ---- results ----
export const ResultsDefault: Story = { args: { initial: { view: "report", report: "USR-03" } } };
export const ResultsOpenedByMeName: Story = {
  args: {
    initial: {
      view: "report",
      report: "USR-03",
      preset: "recent",
      alias: "Recently Logged on Users",
    },
  },
};
export const ResultsServiceAccountsShown: Story = {
  args: { initial: { view: "report", report: "USR-03", showSvc: true } },
};
export const ResultsNeverLoggedOnCaveat: Story = {
  args: { initial: { view: "report", report: "USR-03", preset: "never" } },
};
export const ResultsLongNamesFiltered: Story = {
  args: { initial: { view: "report", report: "USR-01", filter: "Hendriksen" } },
};
export const GroupNestedDomainAdmins: Story = {
  args: {
    initial: { view: "report", report: "GRP-02", preset: "detailed", group: "Domain Admins" },
  },
};
export const GroupBigThousands: Story = {
  args: {
    initial: {
      view: "report",
      report: "GRP-02",
      preset: "detailed",
      group: "SG-Finance-Operations-EMEA-Regional-Approvers-and-Delegates",
    },
  },
};
export const GroupNeedsParameter: Story = {
  args: { initial: { view: "report", report: "GRP-02" } },
};
export const ComputersInactive: Story = { args: { initial: { view: "report", report: "CMP-02" } } };
export const PerDcComplete: Story = { args: { initial: { view: "report", report: "USR-04" } } };

// ---- unhappy paths (spec §5) ----
export const StaleData: Story = {
  args: { initial: { view: "report", report: "PWD-01", scenario: "stale" } },
};
export const NotSyncedYet: Story = {
  args: { initial: { view: "report", report: "USR-01", scenario: "notSynced" } },
};
export const EmptyScope: Story = {
  args: { initial: { view: "report", report: "USR-03", scenario: "emptyScope" } },
};
export const UnsupportedScopeKind: Story = {
  args: { initial: { view: "report", report: "USR-03", scenario: "unsupportedScope" } },
};
export const UnsupportedScopeEntra: Story = {
  args: {
    initial: {
      view: "report",
      report: "USR-03",
      scenario: "unsupportedScope",
      unsupportedKind: "an Entra administrative unit",
    },
  },
};
export const ExpiredResult: Story = {
  args: { initial: { view: "report", report: "USR-03", scenario: "expired" } },
};
export const ExpiredResultExportReruns: Story = {
  args: { initial: { view: "report", report: "USR-03", scenario: "expired", menu: "export" } },
};
export const RunFailed: Story = {
  args: { initial: { view: "report", report: "USR-03", scenario: "failed" } },
};
export const Loading: Story = {
  args: { initial: { view: "report", report: "USR-03", scenario: "loading" } },
};
export const EmptyResultFilter: Story = {
  args: { initial: { view: "report", report: "USR-03", filter: "zzqx" } },
};
export const PerDcRunning: Story = {
  args: { initial: { view: "report", report: "USR-04", scenario: "running" } },
};
export const PerDcPartial: Story = {
  args: { initial: { view: "report", report: "USR-04", scenario: "partialDc" } },
};
export const PerDcOverReadCap: Story = {
  args: { initial: { view: "report", report: "USR-04", scenario: "readCap" } },
};
export const NoExportOrSchedulePermission: Story = {
  args: { perms: NO_EXPORT, initial: { view: "report", report: "USR-03" } },
};

// ---- export ----
export const ExportMenu: Story = {
  args: { initial: { view: "report", report: "USR-03", menu: "export" } },
};
export const ExportMenuEvidencePack: Story = {
  args: {
    initial: {
      view: "report",
      report: "GRP-02",
      preset: "detailed",
      group: "Domain Admins",
      menu: "export",
    },
  },
};
export const ExportOverTenantLimit: Story = {
  args: {
    exportCaps: { CSV: 10_000, XLSX: 10_000 },
    initial: { view: "report", report: "USR-01", preset: "all", menu: "export" },
  },
};
export const ExportOverOneFormatLimit: Story = {
  args: {
    exportCaps: { CSV: 1_000_000, XLSX: 10_000 },
    initial: { view: "report", report: "USR-01", preset: "all", menu: "export" },
  },
};
export const RunDetailsFiles: Story = {
  args: { initial: { view: "report", report: "USR-03", details: true } },
};

// ---- schedule ----
export const ScheduleSheetEmpty: Story = {
  args: { initial: { view: "report", report: "PWD-01", preset: "never", sheet: true } },
};
export const ScheduleSheetReady: Story = {
  args: {
    initial: {
      view: "report",
      report: "PWD-01",
      preset: "never",
      sheet: true,
      sheetState: { preset: "monthly", recipients: ["compliance@example.test"] },
    },
  },
};
export const ScheduleExternalConfirm: Story = {
  args: {
    initial: {
      view: "report",
      report: "PWD-01",
      preset: "never",
      sheet: true,
      sheetState: {
        preset: "monthly",
        recipients: ["compliance@example.test", "auditor@partner.example"],
      },
    },
  },
};
export const ScheduleExternalNotAllowed: Story = {
  args: {
    perms: NO_EXTERNAL,
    initial: {
      view: "report",
      report: "PWD-01",
      preset: "never",
      sheet: true,
      sheetState: { preset: "monthly", recipients: ["auditor@partner.example"], saveAttempt: true },
    },
  },
};
export const ScheduleValidation: Story = {
  args: {
    initial: {
      view: "report",
      report: "PWD-01",
      preset: "never",
      sheet: true,
      sheetState: { saveAttempt: true },
    },
  },
};
export const ScheduleHourlyRefusedForDcReport: Story = {
  args: {
    initial: {
      view: "report",
      report: "USR-04",
      sheet: true,
      sheetState: {
        preset: "custom",
        customHourly: true,
        recipients: ["compliance@example.test"],
        saveAttempt: true,
      },
    },
  },
};
export const SchedulesList: Story = { args: { initial: { view: "schedules" } } };
export const ScheduleDeliveryFailure: Story = {
  args: { initial: { view: "schedules", scheduleOpen: "S-1" } },
};
export const SchedulePausedOwnerDisabled: Story = {
  args: { initial: { view: "schedules", scheduleOpen: "S-4" } },
};
export const ScheduleRanNothingToSend: Story = {
  args: { initial: { view: "schedules", scheduleOpen: "S-3" } },
};
