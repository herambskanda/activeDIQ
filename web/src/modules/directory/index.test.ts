import { describe, expect, it } from "vitest";

import { collectContributions } from "../../app/modules";
import { directoryModule } from ".";

describe("directory module", () => {
  const got = collectContributions([directoryModule]);

  it("registers the Search users palette entry for the route it already registers", () => {
    const entry = got.palette.find((e) => e.id === "directory.search-users");
    expect(entry).toMatchObject({ label: "Search users", route: "/directory/users" });
    expect(entry?.keywords.length).toBeGreaterThan(0);
    expect(got.routes.map((r) => r.path)).toContain(entry?.route);
  });
});
