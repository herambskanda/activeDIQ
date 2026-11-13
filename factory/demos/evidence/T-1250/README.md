build 0c711b72b. Samba schema rangeUpper (docker exec ldbsearch on my lab): samba-rangeUpper.txt
sAM 256, UPN 1024, displayName 256, mail 256, company 64, description 1024, dNSHostName 2048 -> all <= mapper bounds in sync-refusal-bounds.md. operatingSystem/Version/managedBy: no rangeUpper in Samba schema.
Tests: go test -run 'Test_bounds_are|Malformed|Fuzz_map|RefusedEntries' ./internal/directory/sync ok.
