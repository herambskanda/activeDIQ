package main

import (
	"strings"
	"testing"
)

// Clean contracts: exactly the golden RPCs of agent-host-addc-contract.md §2 and
// fileserver-agent.md §3, typed fields only.
const agentHost = `syntax = "proto3";
package skenzeriq.agent.v1;
message Empty {}
message SignedPolicy { bytes payload = 1; bytes signature = 2; }
message SignedKeyset { bytes payload = 1; bytes signature = 2; }
message StageRequest { bytes tuf_metadata = 1; bytes artefact_digest = 2; }
message AckRequest { uint64 through_agent_seq = 1; }
message Status { uint64 policy_seq = 1; }
service Host {
  rpc GetStatus(Empty) returns (Status);
  rpc ApplyPolicy(SignedPolicy) returns (Status);
  rpc ApplyKeyset(SignedKeyset) returns (Status);
  rpc StageUpdate(StageRequest) returns (Status);
  rpc AckEvents(AckRequest) returns (Status);
}
`

const agentAddc = `syntax = "proto3";
package activediq.addc.v1;
message Empty {}
message CollectionState { uint64 last_event_record_id = 1; }
message PasswordPolicy { uint32 min_length = 1; repeated string banned_terms = 2; }
message AddcPolicy { PasswordPolicy password = 1; bool collection_enabled = 2; }
service Addc { rpc GetCollectionState(Empty) returns (CollectionState); }
`

const agentFileserver = `syntax = "proto3";
package activediq.fileserver.v1;
message AclRow { uint32 ace_type = 1; bytes trustee_sid = 2; uint32 mask = 3; }
message ReadAclRequest { string root_id = 1; repeated string components = 2; string operation_id = 3; }
message ReadAclResponse { repeated AclRow rows = 1; bytes digest = 2; }
message ApplyAclRequest { string root_id = 1; repeated string components = 2; bytes base_digest = 3; repeated AclRow diff = 4; }
message ApplyAclResponse { repeated AclRow before = 1; repeated AclRow after = 2; }
message CreateFolderRequest { string root_id = 1; repeated string components = 2; }
message CreateFolderResponse {}
service Fileserver {
  rpc ReadAcl(ReadAclRequest) returns (ReadAclResponse);
  rpc ApplyAcl(ApplyAclRequest) returns (ApplyAclResponse);
  rpc CreateFolder(CreateFolderRequest) returns (CreateFolderResponse);
}
`

func TestAgentCleanContractsPass(t *testing.T) {
	for name, src := range map[string]string{"host": agentHost, "addc": agentAddc, "fileserver": agentFileserver} {
		vs, err := lint(t, src)
		if err != nil || len(vs) != 0 {
			t.Fatalf("%s: want clean, got %v %v", name, vs, err)
		}
	}
}

// TestAgentDenied is TM-F-AGENTCMD: every denied category, tried against the contracts, fails with
// the named rule.
func TestAgentDenied(t *testing.T) {
	type tc struct{ name, src, rule string }
	rpc := func(base, from, to string) string { return strings.Replace(base, from, to, 1) }
	cases := []tc{
		{"exec verb", rpc(agentAddc, "service Addc {", "service Addc { rpc ExecuteCommand(Empty) returns (Empty);"), "AG2"},
		{"run script verb", rpc(agentAddc, "service Addc {", "service Addc { rpc RunScript(Empty) returns (Empty);"), "AG2"},
		{"delete verb", rpc(agentFileserver, "service Fileserver {", "service Fileserver { rpc DeleteFolder(CreateFolderRequest) returns (CreateFolderResponse);"), "AG2"},
		{"file write verb", rpc(agentFileserver, "service Fileserver {", "service Fileserver { rpc WriteFile(CreateFolderRequest) returns (CreateFolderResponse);"), "AG2"},
		{"set owner verb", rpc(agentFileserver, "service Fileserver {", "service Fileserver { rpc SetOwner(CreateFolderRequest) returns (CreateFolderResponse);"), "AG2"},
		{"service change verb", rpc(agentHost, "service Host {", "service Host { rpc RestartService(Empty) returns (Status);"), "AG2"},
		{"registry verb", rpc(agentHost, "service Host {", "service Host { rpc SetRegistryValue(Empty) returns (Status);"), "AG2"},
		{"update outside signed channel", rpc(agentHost, "service Host {", "service Host { rpc DownloadUpdate(Empty) returns (Status);"), "AG2"},
		{"rpc off the golden list", rpc(agentAddc, "service Addc {", "service Addc { rpc Ping(Empty) returns (Empty);"), "AG1"},
		{"golden edit cannot hide a denied verb", rpc(agentFileserver, "service Fileserver {", "service Fileserver { rpc ApplyAclAndRun(CreateFolderRequest) returns (CreateFolderResponse);"), "AG2"},
		{"foreign service", rpc(agentAddc, "service Addc {", "service Debug { rpc Dump(Empty) returns (Empty); }\nservice Addc {"), "AG1"},
		{"server stream", rpc(agentAddc, "returns (CollectionState)", "returns (stream CollectionState)"), "AG3"},
		{"any", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; google.protobuf.Any x = 3;"), "AG4"},
		{"map", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; map<string,string> m = 3;"), "AG4"},
		{"absolute path field", rpc(agentFileserver, "string operation_id = 3;", "string operation_id = 3; string path = 4;"), "AG4"},
		{"path in policy", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; string log_path = 3;"), "AG4"},
		{"free string in policy", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; string note = 3;"), "AG5"},
		{"bytes in policy", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; bytes blob = 3;"), "AG5"},
		{"sddl text", rpc(agentFileserver, "bytes base_digest = 3;", "bytes base_digest = 3; string sddl = 5;"), "AG4"},
		{"password field", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; uint32 password_hash = 3;"), "AG6"},
		{"candidate password string", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; string candidate_password = 3;"), "AG6"},
		{"fail mode in policy", rpc(agentAddc, "bool collection_enabled = 2;", "bool collection_enabled = 2; bool fail_open = 3;"), "AG7"},
		{"proto2", strings.Replace(agentAddc, `syntax = "proto3";`, `syntax = "proto2";`, 1), "AG8"},
	}
	for _, c := range cases {
		src := c.src
		if strings.Contains(src, "google.protobuf.Any") {
			src = strings.Replace(src, "package ", "import \"google/protobuf/any.proto\";\npackage ", 1)
			src = strings.ReplaceAll(src, "google.protobuf.Any x", "google.protobuf.Any x")
		}
		vs, err := lint(t, src)
		if c.rule == "AG8" {
			// proto2 may fail to lint for field-presence reasons; either way a violation or error is required.
			if err == nil && !strings.Contains(rules(vs), c.rule) {
				t.Errorf("%s: want %s, got %q", c.name, c.rule, rules(vs))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: compile: %v", c.name, err)
			continue
		}
		if !strings.Contains(rules(vs), c.rule) {
			t.Errorf("%s: want %s, got %q (%v)", c.name, c.rule, rules(vs), vs)
		}
	}
}

// TestAgentContractsDoNotNeedOperationEnum: agent packages are not operation contracts (no P5).
func TestAgentContractsDoNotNeedOperationEnum(t *testing.T) {
	vs, _ := lint(t, agentAddc)
	if strings.Contains(rules(vs), "P5") {
		t.Fatalf("agent contract held to operation rules: %v", vs)
	}
}
