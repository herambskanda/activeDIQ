package main

// TM-F-AGENTCMD, contract half (T-0144). The agent contracts are not operation contracts: they are
// the closed command set a compromised server could call on a DC or a file server (TM-D13,
// TM-TB12-T3/T4/T10). Packages: skenzeriq.agent.v1 (host), activediq.addc.v1, activediq.fileserver.v1.
// Spec: agent-host-addc-contract.md §2, §3, §6 (R1-R5) and fileserver-agent.md §3.
//
//	AG1 the service/RPC set is a closed golden list. Any added, renamed or foreign RPC fails; the
//	    change needs security-architect approval and an edit of agentGolden below (CODEOWNERS).
//	AG2 no RPC name contains a word of a denied category: exec/spawn/run/shell/command/script
//	    (code execution), delete/remove/purge/wipe/rename/move (destruction), write/upload/put/copy/
//	    file (file content), service/registry (configuration), install/download/fetch/self-update
//	    (update outside the signed channel), owner/takeown/sacl/sddl (ownership and raw descriptors).
//	    Checked on the name even when the RPC is on the golden list, so the golden list cannot be
//	    edited to hide a denied verb without also failing here.
//	AG3 RPCs are unary. The server cannot hold a stream open on the agent (events flow the other
//	    way, through EventIngest.Append).
//	AG4 no field reachable from any RPC input or output, and no declared message field, is a
//	    free-form value: no google.protobuf.Any, no map, no extension, and no string or bytes field
//	    named like a path, URL, command, script, argument, SDDL, regex or pattern. Strings that are
//	    matched, never interpreted, are an explicit allowlist (agentFreeTextAllow).
//	AG5 policy messages (every message reachable from a message named *Policy that is not the
//	    signed envelope) contain no bytes and no string except the allowlist.
//	AG6 no field or message named password/credential/secret/hash/pwd (C15: nothing in the agent
//	    surface carries a password or hash).
//	AG7 no field or message names a fail mode (fail_open/fail_closed/fail_mode): a policy cannot
//	    choose it (C16, TM-Q20).
//	AG8 agent files are syntax proto3 and no file extends an agent message.
//
// What this does not cover and cannot, because the code does not exist yet: numeric bounds of a
// policy (rejection is the agent's runtime test, F1/F2), the root allow-list, path escapes, the
// DC refusal and the SeBackupPrivilege refusal. Those are the lab and agent-test half (follow-up
// ticket named in T-0144's note).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile/linker"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// agentGolden is the closed RPC list: package -> service -> RPC names. agent-host-addc-contract.md
// §2 and fileserver-agent.md §3. CollectFileEvents is agent-initiated (EventIngest.Append) and is
// tolerated here only so the T-0559 contract may declare it; it is not required.
var agentGolden = map[protoreflect.FullName]map[protoreflect.Name]map[protoreflect.Name]bool{
	"skenzeriq.agent.v1": {
		"Host": {"GetStatus": true, "ApplyPolicy": true, "ApplyKeyset": true, "StageUpdate": true, "AckEvents": true},
	},
	"activediq.addc.v1": {
		"Addc": {"GetCollectionState": true},
	},
	"activediq.fileserver.v1": {
		"Fileserver": {"ReadAcl": true, "ApplyAcl": true, "CreateFolder": true, "CollectFileEvents": true},
	},
}

// deniedVerbWords are matched against the lower-case words of an RPC name.
var deniedVerbWords = map[string]string{
	"exec": "code execution", "execute": "code execution", "spawn": "code execution", "run": "code execution",
	"launch": "code execution", "shell": "code execution", "command": "code execution", "script": "code execution",
	"invoke": "code execution", "eval": "code execution", "powershell": "code execution", "cmd": "code execution",
	"delete": "delete", "remove": "delete", "purge": "delete", "wipe": "delete", "unlink": "delete",
	"rename": "delete or move", "move": "delete or move", "truncate": "delete",
	"write": "file content write", "upload": "file content write", "put": "file content write",
	"copy": "file content write", "file": "file content write", "append": "file content write",
	"service": "service/registry change", "registry": "service/registry change", "reg": "service/registry change",
	"install": "update outside the signed channel", "download": "update outside the signed channel",
	"fetch": "update outside the signed channel", "upgrade": "update outside the signed channel",
	"owner": "ownership", "takeown": "ownership", "sacl": "raw descriptor", "sddl": "raw descriptor",
	"privilege": "privilege change",
	"update":    "update outside the signed channel", "patch": "update outside the signed channel",
}

// deniedVerbExceptions are RPC full names whose words match a denied word legitimately: StageUpdate
// stages only a TUF-verified artefact (TM-D12), and CollectFileEvents reads events, not file content.
var deniedVerbExceptions = map[string]bool{
	"CollectFileEvents": true, "StageUpdate": true,
}

// freeTextFragments mark string or bytes fields that could carry a path, URL, command or pattern.
var freeTextFragments = []string{"path", "url", "uri", "command", "cmd", "script", "arg", "sddl", "regex", "pattern", "exe", "shell", "filename", "file_name", "dir", "host", "address"}

// agentFreeTextAllow are the only string fields allowed in policy messages (matched, never
// interpreted). Full field names.
var agentFreeTextAllow = map[string]bool{
	"activediq.addc.v1.PasswordPolicy.banned_terms": true,
}

// policyAllowStrings is the field-name allowlist inside *Policy messages across agent packages:
// banned terms (matched), the local root id, and relative path components (addressed under a
// local root only, fileserver-agent.md §4). They are the sanctioned strings, bounded elsewhere.
var policyAllowStrings = map[string]bool{"banned_terms": true, "root_id": true, "components": true}

// secretFragmentsAgent are refused in any field or message name. "password" alone is allowed on a
// message-typed field and in the *Policy message names, because the addc policy has a legitimate
// `password` rules group (agent-host-addc-contract.md §3); it is refused on a string or bytes field.
var secretFragmentsAgent = []string{"passwd", "pwd", "credential", "secret", "hash"}
var failModeFragments = []string{"fail_open", "fail_closed", "failopen", "failclosed", "fail_mode"}

func isAgent(pkg protoreflect.FullName) bool {
	_, ok := agentGolden[pkg]
	return ok
}

// camelWords splits ReadAcl / StageUpdate / WriteDACL into lower-case words.
func camelWords(s string) []string {
	return strings.Split(strings.ToLower(screamingSnake(s)), "_")
}

// lintAgent applies AG1 to AG8 to every agent package among files.
func lintAgent(files linker.Files) []Violation {
	var vs []Violation
	pkgs := map[protoreflect.FullName]bool{}
	for _, f := range files {
		if isAgent(f.Package()) {
			pkgs[f.Package()] = true
		}
	}
	names := make([]string, 0, len(pkgs))
	for p := range pkgs {
		names = append(names, string(p))
	}
	sort.Strings(names)
	for _, pn := range names {
		pkg := protoreflect.FullName(pn)
		golden := agentGolden[pkg]
		var roots []protoreflect.MessageDescriptor
		for _, f := range files {
			if f.Package() != pkg {
				continue
			}
			if f.Syntax() != protoreflect.Proto3 {
				vs = append(vs, Violation{"AG8", f.Path(), "agent contract files must be syntax proto3"})
			}
			var exts []protoreflect.ExtensionDescriptor
			collectExtensions(f, &exts)
			for _, x := range exts {
				if x.ContainingMessage().ParentFile().Package() == pkg {
					vs = append(vs, Violation{"AG8", string(x.FullName()), "extending an agent message is an unchecked side channel"})
				}
			}
			collectMessages(f.Messages(), &roots)
			for i := 0; i < f.Services().Len(); i++ {
				svc := f.Services().Get(i)
				allowed, svcOK := golden[svc.Name()]
				if !svcOK {
					vs = append(vs, Violation{"AG1", string(svc.FullName()), fmt.Sprintf("service %s is not on the golden list of %s; a new agent service needs security-architect approval and an edit of agentGolden", svc.Name(), pkg)})
				}
				for j := 0; j < svc.Methods().Len(); j++ {
					m := svc.Methods().Get(j)
					pos := string(m.FullName())
					if svcOK && !allowed[m.Name()] {
						vs = append(vs, Violation{"AG1", pos, "RPC is not on the golden list (agent-host-addc-contract.md §2, fileserver-agent.md §3); adding one needs security-architect approval"})
					}
					if !deniedVerbExceptions[string(m.Name())] {
						for _, w := range camelWords(string(m.Name())) {
							if cat, bad := deniedVerbWords[w]; bad {
								vs = append(vs, Violation{"AG2", pos, "RPC name contains `" + w + "`, a verb of the denied category: " + cat + " (TM-D13)"})
								break
							}
						}
					}
					if m.IsStreamingClient() || m.IsStreamingServer() {
						vs = append(vs, Violation{"AG3", pos, "agent RPCs must be unary; events flow agent to server through EventIngest.Append"})
					}
					roots = append(roots, m.Input(), m.Output())
				}
			}
		}
		// Policy closure: messages named *Policy (not the signed envelope).
		policy := map[protoreflect.FullName]bool{}
		for _, m := range roots {
			if strings.HasSuffix(string(m.Name()), "Policy") && !strings.HasPrefix(string(m.Name()), "Signed") {
				walk(m, string(m.FullName()), map[protoreflect.FullName]bool{}, func(_ string, fd protoreflect.FieldDescriptor) {
					policy[fd.ContainingMessage().FullName()] = true
				})
				policy[m.FullName()] = true
			}
		}
		seen := map[protoreflect.FullName]bool{}
		for _, m := range roots {
			lm := strings.ToLower(string(m.Name()))
			for _, frag := range append([]string{"password"}, secretFragmentsAgent...) {
				if strings.Contains(lm, frag) && !(frag == "password" && (strings.HasSuffix(lm, "policy") || strings.HasSuffix(lm, "rules"))) {
					vs = append(vs, Violation{"AG6", string(m.FullName()), "message name looks like it carries a password, credential or hash (C15)"})
					break
				}
			}
			for _, frag := range failModeFragments {
				if strings.Contains(strings.ReplaceAll(lm, "_", ""), strings.ReplaceAll(frag, "_", "")) {
					vs = append(vs, Violation{"AG7", string(m.FullName()), "the fail mode is a CEO decision (TM-Q20) and cannot be a contract message"})
					break
				}
			}
			walk(m, string(m.FullName()), seen, func(_ string, fd protoreflect.FieldDescriptor) {
				parent := fd.ContainingMessage()
				full := string(parent.FullName()) + "." + string(fd.Name())
				lower := strings.ToLower(string(fd.Name()))
				if fd.IsMap() {
					vs = append(vs, Violation{"AG4", full, "map fields are a free-form side channel"})
				}
				if fd.Message() != nil && fd.Message().FullName() == "google.protobuf.Any" {
					vs = append(vs, Violation{"AG4", full, "google.protobuf.Any is not allowed"})
				}
				textual := fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind
				if textual && !agentFreeTextAllow[full] && !policyAllowStrings[string(fd.Name())] {
					for _, frag := range freeTextFragments {
						if hasWordFragment(lower, frag) {
							vs = append(vs, Violation{"AG4", full, "string/bytes field `" + string(fd.Name()) + "` could carry a path, URL, command, script, argument, SDDL or pattern; use typed fields (root_id plus components, a typed ACE row)"})
							break
						}
					}
				}
				if policy[parent.FullName()] && textual && !policyAllowStrings[string(fd.Name())] {
					vs = append(vs, Violation{"AG5", full, "policy messages are typed data within bounds (TM-D14): no bytes or free strings except banned_terms, root_id, components"})
				}
				for _, frag := range append([]string{"password"}, secretFragmentsAgent...) {
					if strings.Contains(lower, frag) && (frag != "password" || textual) {
						vs = append(vs, Violation{"AG6", full, "nothing in the agent surface may carry a password, credential or hash (C15)"})
						break
					}
				}
				for _, frag := range failModeFragments {
					if strings.Contains(lower, frag) {
						vs = append(vs, Violation{"AG7", full, "the fail mode is a CEO decision (TM-Q20); a policy or request cannot choose it"})
						break
					}
				}
			})
		}
	}
	return vs
}

// hasWordFragment reports whether frag appears in name as a whole underscore-delimited word, or as
// a prefix/suffix word of a multi-word name, so `args` and `file_path` match but `partition` does
// not match `art`-style short fragments by accident.
func hasWordFragment(name, frag string) bool {
	for _, w := range strings.Split(name, "_") {
		if w == frag || w == frag+"s" || strings.HasSuffix(w, frag) && len(frag) >= 4 {
			return true
		}
	}
	return strings.Contains(name, frag) && len(frag) >= 5
}

// AgentContractsPresent reports which agent packages the tree declares, for the activation line.
func AgentContractsPresent(files linker.Files) []string {
	have := map[string]bool{}
	for _, f := range files {
		if isAgent(f.Package()) {
			have[string(f.Package())] = true
		}
	}
	var out []string
	for p := range have {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
