#!/usr/bin/env python3
"""Update the native Swift package snapshots from reviewed local checkouts."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2] / 'third-party/BlahDiem'
provenance = {}
for package, argument, modules in [('Diem', 1, ['Diem', 'DiemSwiftCrypto']), ('BlahDiem', 2, ['BlahDiem'])]:
    source = Path(sys.argv[argument]).resolve()
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip():
        raise SystemExit(f'{package} must be committed before vendoring')
    for module in modules:
        destination = root / module
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir()
        for path in (source / 'Sources' / module).glob('*.swift'):
            shutil.copy2(path, destination / path.name)
    shutil.copy2(source / 'LICENSE', root / (package + '.LICENSE'))
    provenance[package] = {'repository': 'https://github.com/UInt8Co/' + ('diem' if package == 'Diem' else package), 'revision': revision}
(root / 'source.json').write_text(json.dumps(provenance, indent=2) + '\n')
