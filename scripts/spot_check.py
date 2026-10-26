#!/usr/bin/env python3
"""Method check: re-ask PyPI about a seeded sample of surveyed projects, file by file.

    python3 -I scripts/spot_check.py results/survey-<run>.json [--n 40] [--seed 7]

The survey reads provenance presence from the Simple JSON API and the publisher
from up to three files. This script takes a different path: for each sampled
project it requests the Integrity API for every file of the recorded latest
version (up to 80 files) and compares presence and publishers with the survey
record. It also checks every project listed as "attested before, not on the
latest release". Output goes to stdout; save it next to the run.
"""
import argparse
import json
import os
import random
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
import provenance_check as pc  # noqa: E402


def recheck(http, p):
    status, doc = http.get_json(f"{pc.PYPI}/pypi/{pc.normalize(p['project'])}/{p['latest_version']}/json")
    files = [f["filename"] for f in doc.get("urls", []) if not f.get("yanked")][:80]
    attested, pubs = 0, set()
    for fn in files:
        prov = pc.fetch_provenance(http, pc.normalize(p["project"]), p["latest_version"], fn)
        if prov:
            attested += 1
            pubs.update(pc.publisher_repo(x) or x.get("email") or "?" for x in prov["publishers"])
    return len(files), attested, pubs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("survey")
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    with open(args.survey) as f:
        run = json.load(f)
    ok = [p for p in run["projects"] if p["status"] == "ok"]
    sample = random.Random(args.seed).sample(ok, args.n)
    regress = [p for p in ok if p["ever_attested"] and p["latest_files_attested"] == 0
               and p["latest_upload"] > p["last_attested_upload"]]
    todo = {p["project"]: p for p in sample + regress}
    http = pc.Http()
    disagree = 0
    print(f"survey {os.path.basename(args.survey)}; sample n={args.n} seed={args.seed}; "
          f"plus {len(regress)} 'attested before' projects")
    for name, p in todo.items():
        n, attested, pubs = recheck(http, p)
        survey_pubs = set(p.get("publisher_repos") or []) | {
            x.get("email") for x in p.get("publishers", []) if x.get("email")}
        checked = min(p["latest_files"], 80)
        same = (attested > 0) == (p["latest_files_attested"] > 0) and (
            not attested or pubs == survey_pubs) and (
            checked < p["latest_files"] or attested == p["latest_files_attested"])
        disagree += not same
        print(f"{'ok  ' if same else 'DIFF'} {name} {p['latest_version']}: integrity API {attested}/{n} attested"
              f" {sorted(pubs) or ''} | survey {p['latest_files_attested']}/{p['latest_files']}"
              f" {sorted(survey_pubs) or ''}")
    print(f"\n{len(todo)} projects rechecked, {disagree} disagree with the survey, "
          f"{http.requests} requests")


if __name__ == "__main__":
    main()
