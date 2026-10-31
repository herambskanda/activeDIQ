import type { ReactNode } from "react";

import "./reports.css";
import type { ApiClient } from "./api";
import { Link } from "./link";
import { ReportSearch } from "./search";

/** The reports screens' page: the title, the way back to the library and the `/` search. */
export function ReportsFrame({
  client,
  children,
}: {
  readonly client: ApiClient;
  readonly children: ReactNode;
}) {
  return (
    <main className="diq-page rp-page">
      <header className="rp-head">
        <h1 className="diq-page__title rp-head__title">
          <Link to="/reports">Reports</Link>
        </h1>
        <ReportSearch client={client} />
      </header>
      {children}
    </main>
  );
}
