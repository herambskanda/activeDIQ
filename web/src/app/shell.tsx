import { collectRoutes, type WebModule } from "./modules";

/**
 * The console shell. It mounts the routes the registered modules contribute. With no module it
 * renders nothing: there are no screens, and no placeholder content, until the first module
 * ships (EP-15).
 */
export function Shell({ modules }: { readonly modules: readonly WebModule[] }) {
  const routes = collectRoutes(modules);
  return (
    <>
      {routes.map((r) => (
        <r.component key={r.path} />
      ))}
    </>
  );
}
