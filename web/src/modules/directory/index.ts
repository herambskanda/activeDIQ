import type { WebModule } from "../../app/modules";
import { UserSearchPage } from "./user-search-page";

/** The directory web module: user search (T-0670). Its ID equals the server module and OpenAPI tag. */
export const directoryModule: WebModule = {
  id: "directory",
  register(r) {
    r.route({ path: "/directory/users", component: UserSearchPage });
  },
};
