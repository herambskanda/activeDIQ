---
name: c19-lessons
description: C19 (TM-D27) build - fixture SDs, new filter-schema attrs, builder field naming, hand-edited pb.go
metadata:
  type: reference
---
- New attribute read in a Find/Read needs an AttrInfo in connector/ad/schema.go (attributeSecurityGUID, rightsGuid were missing); unit fakes do not catch it, the Samba lab did ("UnknownAttribute").
- C19 fails closed on any C19 object without nTSecurityDescriptor: forest() fixtures get a default SD at the end; tests adding groups/GPOs later must set one.
- Builder field and method names share a namespace (c19 field vs c19 method); no protoc here, edit tier0.pb.go by hand incl. rawDesc enum length varint.
- Never run bare `git stash` in the worktree (stash stack is shared); restore by SHA.
- schemaIDGUID/attributeSecurityGUID are SynOctet in the filter schema: match with ldapfilter.Bytes(g.Bytes()), not ldapfilter.GUID (SynGUID only) — ValueKindMismatch only shows on the lab. Test Query.filter() through ldapfilter.Render.
- Broad principal (AU/Everyone) right on a C19 object fails the whole snapshot closed (rule 4); lab tests wanting a WARN exposure must target a non-C19 tier0 object (AdminSDHolder). Always re-run lab for tier0 AND rights.
