#!/usr/bin/env python3
"""Print the Go packages a merge result needs tested: the packages with changed files, everything that imports them
(transitively), and packages whose tests import any of those. Prints ALL for changes that can affect everything."""
import subprocess, sys, collections
base = sys.argv[1]
changed = subprocess.run(['git', 'diff', '--name-only', base, 'HEAD'], capture_output=True, text=True).stdout.split()
if any(f in ('go.mod', 'go.sum', 'Makefile') or f.endswith('.mk') or f.startswith('tools/ci/') for f in changed):
    print('ALL'); sys.exit(0)
fmt = '{{.ImportPath}}|{{.Dir}}|{{join .Imports ","}}|{{join .TestImports ","}}|{{join .XTestImports ","}}'
out = subprocess.run(['go', 'list', '-f', fmt, './...'], capture_output=True, text=True).stdout.splitlines()
root = subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True, text=True).stdout.strip()
pk = {}
for line in out:
    ip, d, imps, timps, xt = (line.split('|') + ['', '', '', ''])[:5]
    pk[ip] = (d, set(filter(None, imps.split(','))), set(filter(None, (timps + ',' + xt).split(','))))
bydir = {d.replace(root + '/', ''): ip for ip, (d, _, _) in pk.items()}
hit = set()
for f in changed:
    parts = f.split('/')
    for i in range(len(parts) - 1, 0, -1):          # nearest package dir at or above the file
        ip = bydir.get('/'.join(parts[:i]))
        if ip: hit.add(ip); break
rev = collections.defaultdict(set)
for ip, (_, imps, _) in pk.items():
    for i in imps: rev[i].add(ip)
closure, todo = set(hit), list(hit)
while todo:
    for r in rev[todo.pop()]:
        if r not in closure: closure.add(r); todo.append(r)
for ip, (_, _, timps) in pk.items():
    if timps & closure: closure.add(ip)
print(' '.join(sorted(closure)))
