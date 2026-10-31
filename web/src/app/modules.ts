import type { ComponentType } from "react";

// EP-15, the web screen module (blueprint §4). A web module is the only way a screen enters the
// console: it registers routes, palette entries and search-result renderers through the Registrar.
// The shell (src/app) and the design system (src/ds) never import src/modules; the generated
// modules.gen.ts, added with the first module, is the only place that names one (blueprint §2
// rule 8).

export interface RouteSpec {
  /** Absolute path, for example "/objects". */
  readonly path: string;
  readonly component: ComponentType;
}

/**
 * A command-palette entry. It opens a screen, so it names the route it opens; start-up fails if no
 * module registered that route, which keeps a dead entry from shipping.
 */
export interface PaletteEntry {
  /** Unique across all modules, for example "directory.search-users". */
  readonly id: string;
  /** What the palette shows. */
  readonly label: string;
  /** Extra words the palette matches on besides the label. */
  readonly keywords: readonly string[];
  /** The absolute path of a registered route. */
  readonly route: string;
}

/**
 * Renders one search result of a registered type. The shape of `result` is the API's search result
 * for that type, which the module that registers the renderer owns.
 */
export type SearchResultRenderer<T = unknown> = ComponentType<{ readonly result: T }>;

export interface Registrar {
  route(spec: RouteSpec): void;
  palette(entry: PaletteEntry): void;
  searchResults(type: string, renderer: SearchResultRenderer): void;
}

/** What the registered modules contribute, collected once at start-up. */
export interface Contributions {
  readonly routes: readonly RouteSpec[];
  readonly palette: readonly PaletteEntry[];
  /** Search-result renderers by result type. */
  readonly searchResults: ReadonlyMap<string, SearchResultRenderer>;
}

export interface WebModule {
  /** The module ID; it equals the server module ID and its OpenAPI tag. */
  readonly id: string;
  register(r: Registrar): void;
}

/**
 * Collects what the given modules register. A duplicate module ID, route path, palette entry ID or
 * search-result type throws, and so does a palette entry naming a route no module registered, so a
 * mistake fails at start-up rather than shadowing a screen or leaving a dead entry. A module that
 * registers no palette entry or renderer is unaffected.
 */
export function collectContributions(modules: readonly WebModule[]): Contributions {
  const ids = new Set<string>();
  const routes = new Map<string, RouteSpec>();
  const palette = new Map<string, { readonly entry: PaletteEntry; readonly module: string }>();
  const searchResults = new Map<string, SearchResultRenderer>();
  for (const m of modules) {
    if (ids.has(m.id)) throw new Error(`duplicate web module id "${m.id}"`);
    ids.add(m.id);
    m.register({
      route(spec) {
        if (!spec.path.startsWith("/")) {
          throw new Error(`module "${m.id}": route path "${spec.path}" must start with "/"`);
        }
        if (routes.has(spec.path)) {
          throw new Error(`module "${m.id}": route "${spec.path}" is already registered`);
        }
        routes.set(spec.path, spec);
      },
      palette(entry) {
        if (entry.id === "" || entry.label.trim() === "") {
          throw new Error(`module "${m.id}": palette entry "${entry.id}" needs an id and a label`);
        }
        const prior = palette.get(entry.id);
        if (prior) {
          throw new Error(
            `module "${m.id}": palette entry "${entry.id}" is already registered by module "${prior.module}"`,
          );
        }
        palette.set(entry.id, { entry, module: m.id });
      },
      searchResults(type, renderer) {
        if (type === "") throw new Error(`module "${m.id}": search-result type must not be empty`);
        if (searchResults.has(type)) {
          throw new Error(`module "${m.id}": search-result type "${type}" is already registered`);
        }
        searchResults.set(type, renderer);
      },
    });
  }
  // Routes of every module are known only now, so a palette entry may name another module's route.
  for (const { entry, module } of palette.values()) {
    if (!routes.has(entry.route)) {
      throw new Error(
        `module "${module}": palette entry "${entry.id}" names route "${entry.route}", which no module registered`,
      );
    }
  }
  return {
    routes: [...routes.values()],
    palette: [...palette.values()].map((p) => p.entry),
    searchResults,
  };
}
