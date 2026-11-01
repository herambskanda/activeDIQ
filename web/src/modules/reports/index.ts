import type { WebModule } from "../../app/modules";
import { LibraryPage } from "./library-page";
import { ReportPage } from "./report-page";

/** The reports web module: library, `/` search, run and results (T-0966). Its ID equals the server module and OpenAPI tag. */
export const reportsModule: WebModule = {
  id: "reports",
  register(r) {
    r.route({ path: "/reports", component: LibraryPage });
    r.route({ path: "/reports/*", component: ReportPage });
  },
};
