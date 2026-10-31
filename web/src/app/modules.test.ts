import { describe, expect, it } from "vitest";

import { collectContributions, type PaletteEntry, type WebModule } from "./modules";

const Screen = () => null;
const mod = (id: string, ...paths: string[]): WebModule => ({
  id,
  register: (r) => {
    for (const path of paths) r.route({ path, component: Screen });
  },
});

const collectRoutes = (modules: readonly WebModule[]) => collectContributions(modules).routes;

const entry = (id: string, route: string): PaletteEntry => ({
  id,
  label: `Open ${id}`,
  keywords: [id],
  route,
});
const withPalette = (id: string, paths: string[], ...entries: PaletteEntry[]): WebModule => ({
  id,
  register: (r) => {
    for (const path of paths) r.route({ path, component: Screen });
    for (const e of entries) r.palette(e);
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

describe("palette entries", () => {
  it("collects entries in registration order, across modules", () => {
    const got = collectContributions([
      withPalette("a", ["/a"], entry("a.open", "/a")),
      withPalette("b", ["/b"], entry("b.open", "/b"), entry("b.again", "/b")),
    ]).palette;
    expect(got.map((e) => e.id)).toEqual(["a.open", "b.open", "b.again"]);
    expect(got[0]).toEqual({
      id: "a.open",
      label: "Open a.open",
      keywords: ["a.open"],
      route: "/a",
    });
  });

  it("lets an entry open a route another module registered", () => {
    const got = collectContributions([
      withPalette("a", [], entry("a.open-b", "/b")),
      withPalette("b", ["/b"]),
    ]);
    expect(got.palette.map((e) => e.route)).toEqual(["/b"]);
  });

  it("leaves a module with no palette unchanged", () => {
    const got = collectContributions([mod("a", "/a")]);
    expect(got.routes.map((r) => r.path)).toEqual(["/a"]);
    expect(got.palette).toEqual([]);
    expect(got.searchResults.size).toBe(0);
  });

  it("rejects a duplicate entry id, even across modules", () => {
    expect(() =>
      collectContributions([
        withPalette("a", ["/a"], entry("x", "/a")),
        withPalette("b", ["/b"], entry("x", "/b")),
      ]),
    ).toThrow(/palette entry "x" is already registered by module "a"/);
  });

  it("rejects an entry whose route no module registered, naming both", () => {
    expect(() =>
      collectContributions([withPalette("a", ["/a"], entry("a.gone", "/missing"))]),
    ).toThrow(
      /module "a": palette entry "a.gone" names route "\/missing", which no module registered/,
    );
  });

  it("rejects an entry with no id or no label", () => {
    expect(() => collectContributions([withPalette("a", ["/a"], entry("", "/a"))])).toThrow(
      /needs an id and a label/,
    );
    expect(() =>
      collectContributions([withPalette("a", ["/a"], { ...entry("a.x", "/a"), label: " " })]),
    ).toThrow(/needs an id and a label/);
  });
});

describe("search-result renderers", () => {
  const Row = () => null;
  const withRenderers = (id: string, ...types: string[]): WebModule => ({
    id,
    register: (r) => {
      for (const t of types) r.searchResults(t, Row);
    },
  });

  it("collects renderers by result type", () => {
    const got = collectContributions([withRenderers("a", "user"), withRenderers("b", "group")]);
    expect([...got.searchResults.keys()]).toEqual(["user", "group"]);
    expect(got.searchResults.get("user")).toBe(Row);
  });

  it("rejects a duplicate type", () => {
    expect(() =>
      collectContributions([withRenderers("a", "user"), withRenderers("b", "user")]),
    ).toThrow(/search-result type "user" is already registered/);
  });

  it("rejects an empty type", () => {
    expect(() => collectContributions([withRenderers("a", "")])).toThrow(/must not be empty/);
  });
});
