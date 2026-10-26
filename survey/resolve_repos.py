#!/usr/bin/env python3
"""Resolve renamed or moved GitHub repositories before calling two names different.

    GITHUB_TOKEN=... python3 -I survey/resolve_repos.py results/survey-<run>.json

A project whose metadata still says github.com/sdispater/pendulum while the
attestation says github.com/python-pendulum/pendulum is the same repository
after a transfer. This stage asks the GitHub API for the canonical name of every
GitHub repository on either side of a mismatch, so the summary can count those
as matches. Without GITHUB_TOKEN it uses the unauthenticated API (60 requests
per hour), which is enough for one run.
"""
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request


def canonical(repo, token):
    owner_repo = repo.split("/", 1)[1]
    req = urllib.request.Request(f"https://api.github.com/repos/{owner_repo}", headers={
        "Accept": "application/vnd.github+json", "User-Agent": "pypi-provenance-check/1.0",
        **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # follows 301 for renames
            return "github.com/" + json.load(resp)["full_name"].lower()
    except urllib.error.HTTPError as e:
        return f"error:{e.code}"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    with open(path) as f:
        run = json.load(f)
    repos = set()
    for p in run["projects"]:
        if p.get("verdict") == "attested-other-repo":
            repos.update(r for r in p.get("publisher_repos", []) + p.get("metadata_repos", [])
                         if r.startswith("github.com/"))
    token = os.environ.get("GITHUB_TOKEN")
    resolved = {r: canonical(r, token) for r in sorted(repos)}
    out = os.path.join(os.path.dirname(path),
                       "repo-resolution-" + os.path.basename(path)[len("survey-"):])
    with open(out, "w") as f:
        json.dump({"survey": os.path.basename(path),
                   "resolved_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                   "repos": resolved}, f, indent=1)
        f.write("\n")
    renamed = {k: v for k, v in resolved.items() if k != v}
    print(f"wrote {out}: {len(resolved)} repositories, {len(renamed)} resolve to another name")
    for k, v in renamed.items():
        print(f"  {k} -> {v}")


if __name__ == "__main__":
    main()
