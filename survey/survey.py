#!/usr/bin/env python3
"""Survey PEP 740 attestations on the latest release of a fixed set of PyPI projects.

    python3 -I survey/survey.py \\
        --top data/top-pypi-packages-2026-10-01-top1000.json \\
        --extra survey/ai-packages.txt

For each project it reads the JSON API (latest version, its files, its metadata
URLs) and the Simple JSON API (every file and whether PyPI has provenance for
it), then fetches the provenance of up to three files of the latest release to
read the Trusted Publisher. It writes one JSON file per run to results/, stamped
with the hashes of the code and the inputs, and never overwrites a run.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
import provenance_check as pc  # noqa: E402

SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def read_extra(path):
    names = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                names.append(line)
    return names


def version_of(filename):
    if filename.endswith(".whl"):
        return filename.split("-")[1]
    for ext in (".tar.gz", ".zip", ".tar.bz2", ".tgz", ".tar"):
        if filename.endswith(ext):
            return filename[: -len(ext)].rsplit("-", 1)[-1]
    return None


def survey_one(http, name):
    rec = {"project": name}
    try:
        status, doc = http.get_json(f"{pc.PYPI}/pypi/{pc.normalize(name)}/json")
        if status == 404:
            rec["status"] = "not-found"
            return rec
        info = doc["info"]
        latest = [f for f in doc.get("urls", []) if not f.get("yanked")]
        rec["latest_version"] = info.get("version")
        rec["latest_upload"] = min((f["upload_time_iso_8601"] for f in latest), default=None)
        rec["metadata_repos"] = pc.metadata_repos(info)

        status, simple = http.get_json(f"{pc.PYPI}/simple/{pc.normalize(name)}/", accept=SIMPLE_JSON)
        files = simple.get("files", []) if simple else []
        prov_by_name = {f["filename"]: bool(f.get("provenance")) for f in files}
        rec["latest_files"] = len(latest)
        attested_latest = [f for f in latest if prov_by_name.get(f["filename"])]
        rec["latest_files_attested"] = len(attested_latest)

        attested_all = sorted((f["upload-time"], f["filename"]) for f in files if f.get("provenance"))
        rec["ever_attested"] = bool(attested_all)
        if attested_all:
            rec["first_attested_upload"] = attested_all[0][0]
            rec["last_attested_upload"] = attested_all[-1][0]
            rec["last_attested_version"] = version_of(attested_all[-1][1])

        if attested_latest:
            sdists = [f for f in attested_latest if f["packagetype"] == "sdist"]
            wheels = [f for f in attested_latest if f["packagetype"] != "sdist"]
            pick = (sdists[:1] + wheels[:1] + wheels[-1:])[:3]
            seen, publishers, predicates = set(), [], set()
            for f in {f["filename"]: f for f in pick}.values():
                prov = pc.fetch_provenance(http, pc.normalize(name), rec["latest_version"], f["filename"])
                if not prov:
                    continue
                predicates.update(prov["predicate_types"])
                for p in prov["publishers"]:
                    key = json.dumps(p, sort_keys=True)
                    if key not in seen:
                        seen.add(key)
                        publishers.append(p)
            rec["publishers"] = publishers
            rec["predicate_types"] = sorted(predicates)
            repos = sorted({pc.publisher_repo(p) for p in publishers} - {None})
            rec["publisher_repos"] = repos
            if not repos:
                rec["verdict"] = "attested-no-repo"
            elif set(repos) & set(rec["metadata_repos"]):
                rec["verdict"] = "attested-match"
            else:
                rec["verdict"] = "attested-other-repo"
        else:
            rec["verdict"] = "no-attestation"
        rec["status"] = "ok"
    except (RuntimeError, KeyError, TypeError) as e:
        rec["status"] = "error"
        rec["error"] = f"{type(e).__name__}: {e}"
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--top", required=True, help="snapshot written by snapshot_top.py")
    ap.add_argument("--extra", help="extra project names, one per line")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "results"))
    ap.add_argument("--limit", type=int, help="only the first N projects (for a smoke test)")
    args = ap.parse_args()

    with open(args.top) as f:
        top = json.load(f)
    projects = {}
    for row in top["rows"]:
        projects[pc.normalize(row["project"])] = {
            "project": row["project"], "rank": row["rank"],
            "download_count": row["download_count"], "lists": ["top"]}
    if args.extra:
        for n in read_extra(args.extra):
            entry = projects.setdefault(pc.normalize(n), {"project": n, "rank": None,
                                                          "download_count": None, "lists": []})
            entry["lists"].append("ai")
    names = list(projects)
    if args.limit:
        names = names[: args.limit]

    started = dt.datetime.now(dt.timezone.utc)
    out_path = os.path.join(args.out_dir, f"survey-{started:%Y%m%dT%H%M%SZ}.json")
    if os.path.exists(out_path):
        sys.exit(f"{out_path} exists")
    http = pc.Http()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        recs = list(pool.map(lambda n: survey_one(http, n), names))
    finished = dt.datetime.now(dt.timezone.utc)

    for rec, key in zip(recs, names):
        rec.update({k: projects[key][k] for k in ("rank", "download_count", "lists")})
    run = {
        "started_utc": started.isoformat(timespec="seconds"),
        "finished_utc": finished.isoformat(timespec="seconds"),
        "code_sha256": {
            "survey/survey.py": sha256_file(os.path.abspath(__file__)),
            "provenance_check.py": sha256_file(os.path.join(ROOT, "provenance_check.py")),
        },
        "inputs": {
            os.path.relpath(args.top, ROOT): sha256_file(args.top),
            **({os.path.relpath(args.extra, ROOT): sha256_file(args.extra)} if args.extra else {}),
        },
        "top_list_last_update": top["last_update"],
        "limit": args.limit,
        "requests": http.requests,
        "retries": http.retried,
        "projects": recs,
    }
    tmp = out_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(run, f, indent=1)
        f.write("\n")
    os.rename(tmp, out_path)
    errors = sum(1 for r in recs if r["status"] != "ok")
    print(f"wrote {out_path}: {len(recs)} projects, {errors} not ok, "
          f"{http.requests} requests, {http.retried} retries, "
          f"{(finished - started).total_seconds():.0f}s")


if __name__ == "__main__":
    main()
