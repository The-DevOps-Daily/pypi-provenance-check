#!/usr/bin/env python3
"""Turn one survey run (plus its repo resolution) into the numbers the post uses.

    python3 -I survey/summarize.py results/survey-<run>.json

Writes results/summary-<run>.json and results/summary-<run>.md. Every category is
recomputed from the recorded fields, so the summary can be rerun without PyPI.
"""
import json
import os
import sys

ATTESTATIONS_ANNOUNCED = "2024-11-14"  # blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/

CATEGORIES = [
    ("match", "attested, publisher repo is the repo the metadata names"),
    ("match-after-rename", "attested, same repo after a rename or transfer"),
    ("separate-public", "attested from a different public repo"),
    ("separate-not-visible", "attested from a repo that is not publicly visible"),
    ("metadata-no-repo", "attested, but the metadata names no GitHub or GitLab repo"),
    ("no-repo-publisher", "attested by a Google Cloud service account (no repo)"),
    ("none", "no attestation on the latest release"),
]


def categorize(p, resolved):
    v = p.get("verdict")
    if v == "no-attestation":
        return "none"
    if v == "attested-match":
        return "match"
    if v == "attested-no-repo":
        return "no-repo-publisher"
    if not p.get("metadata_repos"):
        return "metadata-no-repo"
    pubs = {resolved.get(r, r) for r in p["publisher_repos"]}
    meta = {resolved.get(r, r) for r in p["metadata_repos"]}
    if pubs & meta:
        return "match-after-rename"
    if all(str(resolved.get(r, "")).startswith("error:") for r in p["publisher_repos"]):
        return "separate-not-visible"
    return "separate-public"


def table(rows, resolved):
    counts = {k: 0 for k, _ in CATEGORIES}
    for p in rows:
        counts[categorize(p, resolved)] += 1
    n = len(rows)
    attested = n - counts["none"]
    names_meta = counts["match"] + counts["match-after-rename"]
    return {"projects": n, "counts": counts, "attested": attested,
            "attested_pct": round(100 * attested / n, 1) if n else None,
            "names_metadata_repo": names_meta,
            "names_metadata_repo_pct": round(100 * names_meta / n, 1) if n else None}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    with open(path) as f:
        run = json.load(f)
    res_path = os.path.join(os.path.dirname(path),
                            "repo-resolution-" + os.path.basename(path)[len("survey-"):])
    resolved = {}
    if os.path.exists(res_path):
        with open(res_path) as f:
            resolved = json.load(f)["repos"]
    if run.get("limit"):
        sys.exit("refusing to summarize a --limit smoke-test run")
    projects = [p for p in run["projects"] if p["status"] == "ok"]
    not_ok = [p["project"] for p in run["projects"] if p["status"] != "ok"]
    top = [p for p in projects if "top" in p["lists"]]
    ai = [p for p in projects if "ai" in p["lists"]]
    groups = {
        "top 1-1000": top,
        "top 1-100": [p for p in top if p["rank"] <= 100],
        "top 101-500": [p for p in top if 100 < p["rank"] <= 500],
        "top 501-1000": [p for p in top if p["rank"] > 500],
        f"top 1-1000, latest uploaded on or after {ATTESTATIONS_ANNOUNCED}":
            [p for p in top if (p.get("latest_upload") or "") >= ATTESTATIONS_ANNOUNCED],
        "AI-stack list": ai,
    }
    regressions = sorted(
        (p for p in projects if p["ever_attested"] and p["latest_files_attested"] == 0
         and (p.get("latest_upload") or "") > p["last_attested_upload"]),
        key=lambda p: (p["rank"] is None, p["rank"] or 0, p["project"]))
    partial = [p for p in projects if 0 < p["latest_files_attested"] < p["latest_files"]]
    separate = sorted((p for p in projects if categorize(p, resolved) in
                       ("separate-public", "separate-not-visible", "metadata-no-repo",
                        "match-after-rename")),
                      key=lambda p: (p["rank"] is None, p["rank"] or 0))
    predicate_types = {}
    for p in projects:
        for t in p.get("predicate_types", []):
            predicate_types[t] = predicate_types.get(t, 0) + 1

    summary = {
        "survey": os.path.basename(path), "started_utc": run["started_utc"],
        "top_list_last_update": run["top_list_last_update"], "not_ok": not_ok,
        "groups": {k: table(v, resolved) for k, v in groups.items()},
        "regressions": [{k: p.get(k) for k in ("project", "rank", "lists", "latest_version", "latest_upload",
                                                "last_attested_version", "last_attested_upload")}
                        for p in regressions],
        "regressions_top1000": sum(1 for p in regressions if "top" in p["lists"]),
        "partial": [{k: p.get(k) for k in ("project", "latest_version", "latest_files_attested", "latest_files")}
                    for p in partial],
        "not_matching_metadata": [{k: p.get(k) for k in ("project", "rank", "publisher_repos", "metadata_repos")}
                                  | {"category": categorize(p, resolved)} for p in separate],
        "predicate_types": predicate_types,
    }
    base = os.path.basename(path)[len("survey-"):-len(".json")]
    out_json = os.path.join(os.path.dirname(path), f"summary-{base}.json")
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=1)
        f.write("\n")

    lines = [f"# Survey {base}", "",
             f"Top list: hugovk/top-pypi-packages, updated {run['top_list_last_update']}. "
             f"Survey started {run['started_utc']}. Projects not checked: {len(not_ok)}.", "",
             "| Group | Projects | Attested | Names the metadata repo |", "|---|---|---|---|"]
    for k, t in summary["groups"].items():
        lines.append(f"| {k} | {t['projects']} | {t['attested']} ({t['attested_pct']}%) | "
                     f"{t['names_metadata_repo']} ({t['names_metadata_repo_pct']}%) |")
    lines += ["", "## Categories, top 1-1000", "", "| Category | Projects |", "|---|---|"]
    for key, label in CATEGORIES:
        lines.append(f"| {label} | {summary['groups']['top 1-1000']['counts'][key]} |")
    lines += ["", "## Categories, AI-stack list", "", "| Category | Projects |", "|---|---|"]
    for key, label in CATEGORIES:
        lines.append(f"| {label} | {summary['groups']['AI-stack list']['counts'][key]} |")
    lines += ["", f"## Attested before, not on the latest release ({len(regressions)})", "",
              "| Project | Rank | Latest | Uploaded | Last attested | Uploaded |", "|---|---|---|---|---|---|"]
    for p in regressions:
        lines.append(f"| {p['project']} | {p['rank'] or 'AI list'} | {p['latest_version']} | "
                     f"{p['latest_upload'][:10]} | {p['last_attested_version']} | {p['last_attested_upload'][:10]} |")
    lines += ["", "## Attested, but not by the repo the metadata names", "",
              "| Project | Rank | Publisher repo | Metadata repos | Category |", "|---|---|---|---|---|"]
    for p in separate:
        lines.append(f"| {p['project']} | {p['rank'] or 'AI list'} | {', '.join(p['publisher_repos'])} | "
                     f"{', '.join(p['metadata_repos']) or 'none'} | {categorize(p, resolved)} |")
    lines += ["", "## Partly attested latest releases", ""]
    lines += [f"- {p['project']} {p['latest_version']}: {p['latest_files_attested']} of {p['latest_files']} files"
              for p in partial] or ["- none"]
    lines += ["", f"Predicate types seen: {predicate_types}", ""]
    out_md = os.path.join(os.path.dirname(path), f"summary-{base}.md")
    with open(out_md, "w") as f:
        f.write("\n".join(lines))
    print("\n".join(lines[:16]))
    print(f"\nwrote {out_json} and {out_md}")


if __name__ == "__main__":
    main()
