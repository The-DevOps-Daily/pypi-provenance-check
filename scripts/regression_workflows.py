#!/usr/bin/env python3
"""For projects that attested an earlier release but not the latest one, read the
publish step in their GitHub workflows today.

    GITHUB_TOKEN=... python3 -I scripts/regression_workflows.py results/summary-<run>.json results/survey-<run>.json

It lists each workflow file in the repository the project's metadata names and
prints the lines that upload to PyPI (uv publish, pypa/gh-action-pypi-publish,
twine, poetry, pdm, hatch, flit, maturin) and any `attestations:` setting. This
shows how the project publishes now; it does not prove why an earlier release
had attestations and a later one does not.
"""
import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

PATTERN = re.compile(r"(uv publish[^\n]*|pypa/gh-action-pypi-publish@\S+|twine upload[^\n]*|poetry publish[^\n]*|"
                     r"pdm publish[^\n]*|hatch publish[^\n]*|flit publish[^\n]*|maturin upload[^\n]*|"
                     r"attestations:\s*\S+)")


def gh(path, token):
    req = urllib.request.Request(f"https://api.github.com/{path}", headers={
        "Accept": "application/vnd.github+json", "User-Agent": "pypi-provenance-check/1.0",
        **({"Authorization": f"Bearer {token}"} if token else {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        summary = json.load(f)
    with open(sys.argv[2]) as f:
        survey = {p["project"]: p for p in json.load(f)["projects"]}
    token = os.environ.get("GITHUB_TOKEN")
    print(f"checked {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}")
    seen = set()
    for reg in summary["regressions"]:
        repos = [r for r in survey[reg["project"]].get("metadata_repos", []) if r.startswith("github.com/")]
        print(f"\n{reg['project']} {reg['latest_version']} (last attested {reg['last_attested_version']})")
        if not repos:
            print("  no GitHub repository in the metadata: not inspected")
        for repo in repos[:2]:
            owner_repo = repo.split("/", 1)[1]
            if owner_repo in seen:
                print(f"  {repo}: same repository as above")
                continue
            seen.add(owner_repo)
            try:
                files = gh(f"repos/{owner_repo}/contents/.github/workflows", token)
            except urllib.error.HTTPError as e:
                print(f"  {repo}: workflows not readable (HTTP {e.code})")
                continue
            found = False
            for f in files:
                if not f["name"].endswith((".yml", ".yaml")):
                    continue
                body = base64.b64decode(gh(f"repos/{owner_repo}/contents/.github/workflows/{f['name']}",
                                           token)["content"]).decode("utf-8", "replace")
                hits = sorted({m.strip() for m in PATTERN.findall(body)})
                if hits:
                    found = True
                    print(f"  {repo} {f['name']}: " + " | ".join(h[:90] for h in hits))
            if not found:
                print(f"  {repo}: no PyPI upload step found in .github/workflows")


if __name__ == "__main__":
    main()
