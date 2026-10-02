// Package apitypes holds the contract types every API tag shares (ADR-0004 rule 4).
//
// It has two halves. The hand-written half is this directory's non-generated files: the scalars
// (UUID, Date, Timestamp, Int64String), Opt for merge-patch members, the violation collector and the
// decode helpers the generated decoders call. The generated half is every *.gen.go file, emitted by
// tools/gen/api from api/openapi/shared/: the shared schemas and one constructor per problem slug.
//
// Every type here that can appear in an API Input or Output decodes through encoding/json/v2
// methods only (UnmarshalJSONFrom, MarshalJSONTo). There is no v1 json.Unmarshaler or
// json.Marshaler anywhere in this package, so a strict decode reaches every nested value
// (ADR-0004 rule 4, the type-closure rule).
package apitypes
