# T-1194 QA evidence (build 89ff1d206, Samba lab bf44d9ad, run 2026-11-02)
- lab-feed.txt, lab-feed-rerun.txt: go test -tags lab ./internal/connector/read -run TestLabFeed -v — PASS x4, twice (AC1-AC4)
- ac5-labserver.txt: go test -tags lab ./internal/compose/server -run TestLabServerServesChangeFeed -v — PASS pg16+pg18
- ac5-prod-vs-lab-symbols.txt: cmd/server built without/with -tags lab: labServer symbols 0 vs 19
- ac1-directory-oracle.txt: rootDSE + NTDS Settings objectGUID/invocationId read straight from the DC (ldapsearch)
- unit-race.txt: go test -race read, compose/connector, ad — PASS
No UI in this ticket (gRPC only): no controls/screens to click.

## Re-run on merged head e33c3e10a (2026-11-06)
Plain+lab build, vet, race tests (read, compose/connector, ad) PASS; TestLabFeed x4 and TestLabServerServesChangeFeed (pg16, pg18) PASS on Samba; prod cmd/server labServer symbols: 0. Output: rerun-merged-e33c3e10a.txt

## Re-run on merged head 872d69a50 (2026-11-13): build plain+lab, race tests connector+compose, TestLabFeed x4, TestLabServerServesChangeFeed pg16+pg18 PASS on live Samba lab; prod server labServer symbols 0. Output: rerun-merged-872d69a50.txt
