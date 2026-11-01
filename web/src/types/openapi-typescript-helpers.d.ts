// Stands in for `openapi-typescript-helpers` (tsconfig `paths`) inside the type checker only; no
// runtime code imports it. openapi-fetch maps every response through `Readable<T>`, whose
// `T extends object` branch treats the open-enum member `(string & {})` as an object and rebuilds it
// as a copy of `String`'s members, so `hybrid.state` stops matching the declared component type.
// The two aliases below are the upstream ones with one extra first branch: a string passes through
// untouched. Everything else in the package is re-exported as it is. Drop this file, and the
// tsconfig `paths` entry, when upstream handles `string & {}` (openapi-typescript-helpers 0.1.0).
import type { $Read, $Write } from "../../node_modules/openapi-typescript-helpers/dist/index";

export * from "../../node_modules/openapi-typescript-helpers/dist/index";

export type Readable<T> =
  T extends $Write<unknown>
    ? never
    : T extends string
      ? T
      : T extends $Read<infer U>
        ? Readable<U>
        : T extends (infer E)[]
          ? Readable<E>[]
          : T extends object
            ? {
                [K in keyof T as NonNullable<T[K]> extends $Write<unknown> ? never : K]: Readable<
                  T[K]
                >;
              }
            : T;

export type Writable<T> =
  T extends $Read<unknown>
    ? never
    : T extends string
      ? T
      : T extends $Write<infer U>
        ? Writable<U>
        : T extends (infer E)[]
          ? Writable<E>[]
          : T extends object
            ? {
                [K in keyof T as NonNullable<T[K]> extends $Read<unknown> ? never : K]: Writable<
                  T[K]
                >;
              } & {
                [K in keyof T as NonNullable<T[K]> extends $Read<unknown> ? K : never]?: never;
              }
            : T;
