#!/usr/bin/env python3
"""Save a fixed snapshot of the most downloaded PyPI projects.

Source: https://github.com/hugovk/top-pypi-packages (30-day download counts,
refreshed monthly). The survey reads the saved file, never the live list, so a
rerun months later checks the same projects.

    python3 -I survey/snapshot_top.py --top 1000
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request

URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--top", type=int, default=1000)
    ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__), "..", "data"))
    args = ap.parse_args()

    req = urllib.request.Request(URL, headers={"User-Agent": "pypi-provenance-check/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    doc = json.loads(raw)
    day = doc["last_update"].split()[0]
    rows = doc["rows"][: args.top]
    out = {
        "source": URL,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "last_update": doc["last_update"],
        "window": "30 days of downloads ending at last_update (hugovk/top-pypi-packages)",
        "top": args.top,
        "rows": [
            {"rank": i + 1, "project": r["project"], "download_count": r["download_count"]}
            for i, r in enumerate(rows)
        ],
    }
    path = os.path.join(args.out_dir, f"top-pypi-packages-{day}-top{args.top}.json")
    if os.path.exists(path):
        sys.exit(f"{path} exists; refusing to overwrite a fixed snapshot")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(f"wrote {os.path.relpath(path)}: {len(rows)} projects, list updated {doc['last_update']}")


if __name__ == "__main__":
    main()
