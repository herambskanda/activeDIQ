import type { WebModule } from "../../app/modules";
import { UserSearchPage } from "./user-search-page";

const USERS_PATH = "/directory/users";

/** The directory web module: user search (T-0670). Its ID equals the server module and OpenAPI tag. */
export const directoryModule: WebModule = {
  id: "directory",
  register(r) {
    r.route({ path: USERS_PATH, component: UserSearchPage });
    r.palette({
      id: "directory.search-users",
      label: "Search users",
      keywords: ["find", "user", "account", "people", "directory"],
      route: USERS_PATH,
    });
  },
};
