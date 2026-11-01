import type { Meta, StoryObj } from "@storybook/react-vite";

import { Console } from "./Console";

const meta = {
  title: "Prototype/Console",
  component: Console,
  parameters: {
    docs: {
      description: {
        component:
          "Design prototype (T-0672). Every name, code and number is SAMPLE data from fixtures.ts. Interaction counter at the top compares against the top-20 benchmark budget.",
      },
    },
  },
} satisfies Meta<typeof Console>;
export default meta;
type Story = StoryObj<typeof meta>;

/** Start here: press / or click a tile, then walk the whole reset. Sample code for the caller is shown in the sheet. */
export const EndToEnd: Story = {};
export const HomeResetTask: Story = { args: { initial: { searchOpen: true, intent: "reset" } } };

export const SearchResults: Story = { args: { initial: { searchOpen: true, query: "ra" } } };
export const SearchLongNames: Story = {
  args: { initial: { searchOpen: true, query: "hendriksen" } },
};
export const SearchNoMatch: Story = { args: { initial: { searchOpen: true, query: "zzqx" } } };
export const SearchLoading: Story = {
  args: { latencyMs: 600000, initial: { searchOpen: true, query: "priya" } },
};
export const SearchError: Story = {
  args: { failFirstSearch: true, initial: { searchOpen: true, query: "priya" } },
};

export const ObjectLocked: Story = { args: { initial: { user: "priya.raman" } } };
export const ObjectLongNameNoFactor: Story = {
  args: { initial: { user: "j.hendriksen-vanderberg" } },
};
export const ObjectUnicode: Story = { args: { initial: { user: "李伟" } } };

export const ResetVerify: Story = { args: { initial: { user: "priya.raman", sheet: true } } };
export const ResetNoFactorFallback: Story = {
  args: { initial: { user: "j.hendriksen-vanderberg", sheet: true } },
};
export const ResetPermissionDenied: Story = { args: { initial: { user: "李伟", sheet: true } } };
export const ResetProtectedAccount: Story = {
  args: { initial: { user: "hannah.okafor", sheet: true } },
};
export const ResetNotLocked: Story = { args: { initial: { user: "p.ramanathan", sheet: true } } };
