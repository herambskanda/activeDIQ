import { describe, expect, it } from "vitest";

import { collectRoutes, matchRoute, type WebModule } from "./modules";

const Screen = () => null;
const mod = (id: string, ...paths: string[]): WebModule => ({
  id,
  register: (r) => {
    for (const path of paths) r.route({ path, component: Screen });
  },
});

describe("collectRoutes", () => {
  it("collects the routes of every module", () => {
    expect(collectRoutes([mod("a", "/a"), mod("b", "/b", "/b/x")]).map((r) => r.path)).toEqual([
      "/a",
      "/b",
      "/b/x",
    ]);
  });

  it("returns nothing for no modules", () => {
    expect(collectRoutes([])).toEqual([]);
  });

  it("rejects a duplicate module id", () => {
    expect(() => collectRoutes([mod("a", "/a"), mod("a", "/b")])).toThrow(/duplicate web module/);
  });

  it("rejects a duplicate route path", () => {
    expect(() => collectRoutes([mod("a", "/x"), mod("b", "/x")])).toThrow(/already registered/);
  });

  it("rejects a relative route path", () => {
    expect(() => collectRoutes([mod("a", "x")])).toThrow(/must start with/);
  });
});

describe("matchRoute", () => {
  const routes = collectRoutes([mod("a", "/a", "/a/*", "/a/b/*", "/c")]);
  it("prefers an exact path", () => {
    expect(matchRoute(routes, "/a")?.path).toBe("/a");
  });
  it("matches children of a prefix route, longest first", () => {
    expect(matchRoute(routes, "/a/x")?.path).toBe("/a/*");
    expect(matchRoute(routes, "/a/b/c")?.path).toBe("/a/b/*");
  });
  it("does not match the prefix itself, a sibling or nothing", () => {
    expect(matchRoute(routes, "/c/x")).toBeUndefined();
    expect(matchRoute(routes, "/ab")).toBeUndefined();
  });
});
