#!/usr/bin/env python3
"""Rebuild the bounded scanner's low-priority name corpus from pinned local source checkouts.

Usage: python3 scripts/build-header-influence-discovery.py PARAM_MINER_DIR KNOWN_HEADER_DB_DIR
No network requests. Header existence is not proof of request semantics or vulnerability.
"""
import csv
import json
from pathlib import Path
import re
import subprocess
import sys

param, known = map(Path, sys.argv[1:3])
root = Path(__file__).resolve().parents[1]
resource = root / 'src/main/resources/com/b3xal/headeranalyzer'
resource.mkdir(parents=True, exist_ok=True)


def revision(path):
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()


param_rev, known_rev = revision(param), revision(known)
param_url = f'https://github.com/PortSwigger/param-miner/blob/{param_rev}/resources/headers'
known_url = f'https://github.com/pichillilorenzo/known-http-header-db/blob/{known_rev}/dist/db.json'
db = json.loads((known / 'dist/db.json').read_text())
response_only = {name.lower() for name, entry in db.items()
                 if 'response' in (entry.get('type') or []) and 'request' not in (entry.get('type') or [])}
blocked = {'host', 'connection', 'content-length', 'transfer-encoding', 'te', 'trailer', 'upgrade',
           'expect', 'accept-encoding', 'content-encoding', 'content-type', 'content-range', 'range',
           'keep-alive', 'proxy-connection', 'http2-settings',
           'destination', 'overwrite', 'depth', 'lock-token', 'if', 'max-forwards',
           'x-http-method', 'next-action', 'x-middleware-subrequest', 'x-envoy-original-dst-host'}
sensitive = re.compile(r'authorization|authenticate|cookie|token|nonce|secret|password|passwd|api[-_]?key|csrf|xsrf|signature|credential|client-cert|session|purge|invalidat|method[-_]?override', re.I)
entries = {}
for line in (param / 'resources/headers').read_text().splitlines():
    name = line.strip().lower().split('~', 1)[0]
    if name:
        entries[name] = param_url
for name, entry in db.items():
    if 'request' in (entry.get('type') or []):
        entries[name.lower()] = known_url
entries = {name: source for name, source in entries.items()
           if re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]{1,128}", name)
           and name not in response_only and name not in blocked
           and not sensitive.search(name) and not name.startswith('x-quimera-')}
with (resource / 'header-influence-discovery.tsv').open('w', newline='') as file:
    file.write('# name\tvalueKind\tseed\tfamily\tsourceUrl\n')
    writer = csv.writer(file, delimiter='\t', lineterminator='\n')
    for name, source in sorted(entries.items()):
        writer.writerow([name, 'TOKEN', '', 'discovery', source])

licenses = resource / 'licenses'
licenses.mkdir(exist_ok=True)
(licenses / 'known-http-header-db-ISC.txt').write_text((known / 'LICENSE').read_text())
(licenses / 'param-miner-NOTICE.txt').write_text((param / 'LICENSE').read_text()
    + '\nQuimera changes: names normalized/deduplicated; templates separated; response-only and '
      'sensitive/protocol fields excluded; provenance columns added. Corpus used for name discovery only.\n')
(licenses / 'Apache-2.0.txt').write_text((root / 'docs/research/header-probes/APACHE-2.0.txt').read_text())
print(json.dumps({'discovery_names': len(entries), 'known_db_names': len(db),
                  'param_revision': param_rev, 'known_revision': known_rev}))
