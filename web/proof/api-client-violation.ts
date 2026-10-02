// Deliberate violations of ADR-0004 rule 12. `make ci-proof` lints this file with --no-ignore and
// requires every rule to fire.
import axios from "axios";
import { get } from "node-fetch";
import createClient from "openapi-fetch";

export const a = fetch("/x");
export const b = new XMLHttpRequest();
export const c = new EventSource("/x");
export const d = window.fetch("/x");
export const e = "/api/v1/users";
export const f = `/api/v1/users/${a}`;
export const g = import("ky");
export { axios, get, createClient };
