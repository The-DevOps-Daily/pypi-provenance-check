#!/usr/bin/env python3
"""Attestation history of one PyPI project, release by release.

    python3 -I scripts/litellm_history.py [project]      # default: litellm

Reads the Simple JSON API once (every file and whether PyPI holds provenance for
it), groups files by upload day and version, and fetches the provenance of the
first and last attested release to show who the publisher was. Writes
results/<project>-attestation-history-<UTC>.json and prints the runs of
attested and unattested releases.
"""
import datetime as dt
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
import provenance_check as pc  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "survey"))
from survey import version_of  # noqa: E402


def main():
    project = sys.argv[1] if len(sys.argv) > 1 else "litellm"
    http = pc.Http()
    _, simple = http.get_json(f"{pc.PYPI}/simple/{pc.normalize(project)}/",
                              accept="application/vnd.pypi.simple.v1+json")
    releases = {}
    for f in simple["files"]:
        v = version_of(f["filename"])
        r = releases.setdefault(v, {"version": v, "first_upload": f["upload-time"], "files": 0,
                                    "attested": 0, "example": None})
        r["files"] += 1
        r["first_upload"] = min(r["first_upload"], f["upload-time"])
        if f.get("provenance"):
            r["attested"] += 1
            r["example"] = r["example"] or f["filename"]
    ordered = sorted(releases.values(), key=lambda r: r["first_upload"])
    runs = []
    for r in ordered:
        state = r["attested"] > 0
        if not runs or runs[-1]["attested"] != state:
            runs.append({"attested": state, "first": r["version"], "first_upload": r["first_upload"],
                         "last": r["version"], "last_upload": r["first_upload"], "releases": 0})
        runs[-1].update(last=r["version"], last_upload=r["first_upload"])
        runs[-1]["releases"] += 1
    publishers = {}
    attested = [r for r in ordered if r["attested"]]
    for r in attested:  # one attested file per attested release
        prov = pc.fetch_provenance(http, pc.normalize(project), r["version"], r["example"])
        publishers[r["version"]] = prov
    removed = [v for v in ("1.107.0",) if project == "litellm" and v not in releases]
    now = dt.datetime.now(dt.timezone.utc)
    out = {"project": project, "checked_utc": now.isoformat(timespec="seconds"),
           "releases_on_pypi": len(ordered), "runs": runs, "publishers": publishers,
           "not_on_pypi": removed, "releases": ordered}
    path = os.path.join(ROOT, "results", f"{project}-attestation-history-{now:%Y%m%dT%H%M%SZ}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(f"{project}: {len(ordered)} releases on PyPI, checked {out['checked_utc']}")
    for run in runs:
        label = "attested  " if run["attested"] else "no attest."
        print(f"  {label} {run['releases']:>4} releases  {run['first']} ({run['first_upload'][:10]})"
              f" .. {run['last']} ({run['last_upload'][:10]})")
    seen = {}
    for v, prov in publishers.items():
        pubs = "; ".join(pc.publisher_label(p) for p in (prov or {}).get("publishers", [])) or "none"
        seen.setdefault(pubs, []).append(v)
    for pubs, versions in seen.items():
        print(f"  publisher on {len(versions)} of {len(publishers)} attested releases"
              f" ({versions[0]} .. {versions[-1]}): {pubs}")
    for v in removed:
        print(f"  {v}: not on PyPI (removed on 21 Oct 2026)")
    print(f"wrote {os.path.relpath(path, ROOT)}")


if __name__ == "__main__":
    main()
