module github.com/skenzeriq/activediq

go 1.27.3

require (
	github.com/beevik/etree v1.7.0
	github.com/bufbuild/protocompile v0.14.1
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/go-krb5/krb5 v0.1.1-0.20260926041222-f89757a5d4ed
	github.com/go-ldap/ldap/v3 v3.4.13
	github.com/jackc/pgx/v5 v5.9.2
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/russellhaering/goxmldsig v1.6.1
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.41.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/sys v0.48.0
	golang.org/x/text v0.42.0
	golang.org/x/tools v0.49.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/Azure/go-ntlmssp v0.1.0 // indirect
	github.com/go-crypt/x v0.4.17 // indirect
	github.com/go-krb5/x v0.4.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
)

tool (
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)
