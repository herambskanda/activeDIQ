import type { WebModule } from "../../app/modules";
import { SEARCH_PATH } from "./search-results-model";
import { SearchResultsPage } from "./search-results-page";
import { UserSearchPage } from "./user-search-page";

const USERS_PATH = "/directory/users";

/** The directory web module: user search (T-0670) and the full search results page (T-1100). Its ID equals the server module and OpenAPI tag. */
export const directoryModule: WebModule = {
  id: "directory",
  register(r) {
    r.route({ path: USERS_PATH, component: UserSearchPage });
    r.route({ path: SEARCH_PATH, component: SearchResultsPage });
    r.palette({
      id: "directory.search-users",
      label: "Search users",
      keywords: ["find", "user", "account", "people", "directory"],
      route: USERS_PATH,
    });
  },
};
