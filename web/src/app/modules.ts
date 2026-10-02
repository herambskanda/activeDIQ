import type { ComponentType } from "react";

// EP-15, the web screen module (blueprint §4). A web module is the only way a screen enters the
// console: it registers routes through the Registrar. The shell (src/app) and the design system
// (src/ds) never import src/modules; the generated modules.gen.ts, added with the first module,
// is the only place that names one (blueprint §2 rule 8).

export interface RouteSpec {
  /** Absolute path, for example "/objects". */
  readonly path: string;
  readonly component: ComponentType;
}

export interface Registrar {
  route(spec: RouteSpec): void;
}

export interface WebModule {
  /** The module ID; it equals the server module ID and its OpenAPI tag. */
  readonly id: string;
  register(r: Registrar): void;
}

/**
 * Collects the routes of the given modules. A duplicate module ID or route path throws, so a
 * mistake fails at start-up rather than shadowing a screen.
 */
export function collectRoutes(modules: readonly WebModule[]): readonly RouteSpec[] {
  const ids = new Set<string>();
  const routes = new Map<string, RouteSpec>();
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
    });
  }
  return [...routes.values()];
}
