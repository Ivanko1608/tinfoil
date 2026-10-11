#!/usr/bin/env python3
"""Build dist/tinfoil.zip for uploading to claude.ai (Settings > Capabilities > Skills).

Deterministic (fixed timestamps, sorted entries) so CI can check the committed
zip matches the source.
"""
import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "tinfoil")
OUT = os.path.join(ROOT, "dist", "tinfoil.zip")

files = []
for dp, dns, fns in os.walk(SKILL):
    dns[:] = sorted(d for d in dns if d != "__pycache__")
    files += [os.path.join(dp, f) for f in fns if not f.endswith(".pyc")]

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(files):
        arc = os.path.join("tinfoil", os.path.relpath(f, SKILL))
        info = zipfile.ZipInfo(arc, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o755 if f.endswith(".py") else 0o644) << 16
        with open(f, "rb") as fh:
            z.writestr(info, fh.read())
print(f"wrote {os.path.relpath(OUT, ROOT)} ({len(files)} files)")
