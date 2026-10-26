#!/usr/bin/env python3
"""Ask PyPI who published the exact files you installed or locked.

For each distribution it finds, it identifies the exact PyPI file (by the hash in
a lock file, or by the wheel tags recorded in the installed .dist-info), fetches
that file's provenance from PyPI's Integrity API, and reports:

  attested-match       a Trusted Publisher attestation names a repository that
                       the release's own metadata (Project-URL) also names
  attested-other-repo  attested, but by a repository the metadata does not name
  attested-no-repo     attested by a publisher without a repository (Google Cloud)
  no-attestation       PyPI has no attestation for this file
  not-on-pypi          this version is not on PyPI (removed, never published,
                       or installed from another index)
  hash-not-on-pypi     a hash in your lock file matches no file of this release
  not-from-index       installed from a local path, URL or VCS (direct_url.json)
  file-unknown         installed wheel tags match no file of this release
  error                PyPI could not be reached for this distribution

It reads PyPI's record of the attestation. PyPI verified the signature at upload
time; this script does not repeat the Sigstore verification. To verify a file
yourself, use `pypi-attestations verify pypi --repository <url> pypi:<file>`.

It never imports or runs code from the environment it checks.

Exit codes: 0 ok, 1 alert (not-on-pypi, hash-not-on-pypi, or a pinned publisher
changed), 2 usage error, 3 policy failure (--require-attestation or
--require-repo-match), 4 incomplete (network errors).

Python 3.11+ standard library.
"""
import argparse
import base64
import email.parser
import gzip
import itertools
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

PYPI = "https://pypi.org"
USER_AGENT = "pypi-provenance-check/1.0 (+https://github.com/The-DevOps-Daily/pypi-provenance-check)"
REPO_HOSTS = ("github.com", "gitlab.com")
# Path segments after owner/repo that are pages of the repo, not part of its name.
REPO_PAGE_SEGMENTS = {"-", "tree", "blob", "issues", "pulls", "releases", "wiki", "actions",
                      "discussions", "security", "graphs", "network", "commits", "tags",
                      "compare", "pull", "merge_requests", "pipelines", "raw"}


# --------------------------------------------------------------------------- http

class Http:
    """Small JSON client with retries. Counts what it did, for the run record."""

    def __init__(self, retries=4, timeout=60):
        self.retries = retries
        self.timeout = timeout
        self.requests = 0
        self.retried = 0

    def get_json(self, url, accept="application/json"):
        """Return (status, parsed JSON or None). 404 is a normal answer, not an error."""
        last = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT, "Accept": accept, "Accept-Encoding": "gzip"})
            self.requests += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    if resp.headers.get("Content-Encoding") == "gzip":
                        body = gzip.decompress(body)
                    return resp.status, json.loads(body)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return 404, None
                last = f"HTTP {e.code}"
                if e.code not in (429, 500, 502, 503, 504):
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
                last = f"{type(e).__name__}: {e}"
            self.retried += 1
            time.sleep(min(30, 2 ** attempt))
        raise RuntimeError(f"GET {url} failed: {last}")


# ----------------------------------------------------------------- names and repos

def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def repo_from_url(url):
    """'https://github.com/Owner/Repo/tree/main' -> 'github.com/owner/repo'."""
    if not url or not isinstance(url, str):
        return None
    try:
        p = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host not in REPO_HOSTS:
        return None
    parts = [s for s in p.path.split("/") if s]
    if host == "github.com":
        parts = parts[:2]
    else:  # GitLab allows nested groups: keep segments until a page segment
        keep = []
        for s in parts:
            if s in REPO_PAGE_SEGMENTS:
                break
            keep.append(s)
        parts = keep
    if len(parts) < 2:
        return None
    if parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]
    return host + "/" + "/".join(parts).lower()


def metadata_repos(info):
    """Repositories named by a release's metadata: every Project-URL plus Home-page."""
    urls = list((info.get("project_urls") or {}).values())
    urls += [info.get("home_page"), info.get("download_url")]
    return sorted({r for r in map(repo_from_url, urls) if r})


def publisher_repo(pub):
    kind = (pub.get("kind") or "").lower()
    repo = pub.get("repository")
    if not repo:
        return None
    if kind == "github":
        return "github.com/" + repo.lower()
    if kind == "gitlab":
        return "gitlab.com/" + repo.lower()
    return None


def publisher_label(pub):
    if not pub:
        return "none"
    bits = [pub.get("kind") or "?"]
    for key in ("repository", "workflow", "environment", "email"):
        if pub.get(key):
            bits.append(f"{key}={pub[key]}")
    return " ".join(bits)


# ------------------------------------------------------------------ PyPI lookups

def fetch_provenance(http, name, version, filename):
    """None when PyPI has no provenance for the file, else publishers and predicate types."""
    url = (f"{PYPI}/integrity/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/"
           f"{urllib.parse.quote(filename)}/provenance")
    status, doc = http.get_json(url, accept="application/vnd.pypi.integrity.v1+json")
    if status == 404 or not doc:
        return None
    publishers, predicates = [], set()
    for bundle in doc.get("attestation_bundles", []):
        publishers.append(bundle.get("publisher") or {})
        for att in bundle.get("attestations", []):
            try:
                stmt = json.loads(base64.b64decode(att["envelope"]["statement"]))
                predicates.add(stmt.get("predicateType"))
            except (KeyError, ValueError, TypeError):
                predicates.add("unreadable")
    return {"publishers": publishers, "predicate_types": sorted(p for p in predicates if p)}


def release_json(http, name, version):
    status, doc = http.get_json(f"{PYPI}/pypi/{urllib.parse.quote(normalize(name))}/"
                                f"{urllib.parse.quote(version)}/json")
    return None if status == 404 else doc


# --------------------------------------------------------- wheel tag matching

def wheel_tags_from_filename(filename):
    stem = filename[:-4]
    parts = stem.split("-")
    if len(parts) < 5:
        return set()
    py, abi, plat = parts[-3], parts[-2], parts[-1]
    return {"-".join(t) for t in itertools.product(py.split("."), abi.split("."), plat.split("."))}


# ---------------------------------------------------------------- collectors

def find_site_packages(path):
    """A venv root, a site-packages directory, or any directory holding them."""
    path = os.path.abspath(path)
    if os.path.basename(path) in ("site-packages", "dist-packages"):
        return [path]
    found = []
    for root, dirs, _files in os.walk(path):
        depth = root[len(path):].count(os.sep)
        if os.path.basename(root) in ("site-packages", "dist-packages"):
            found.append(root)
            dirs[:] = []
            continue
        if depth >= 6:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
    return sorted(found)


def installed_dists(site_packages):
    out = []
    for entry in sorted(os.listdir(site_packages)):
        if not entry.endswith(".dist-info"):
            continue
        d = os.path.join(site_packages, entry)
        meta_path = os.path.join(d, "METADATA")
        if not os.path.isfile(meta_path):
            continue
        with open(meta_path, encoding="utf-8", errors="replace") as f:
            meta = email.parser.Parser().parse(f, headersonly=True)
        tags = set()
        wheel_path = os.path.join(d, "WHEEL")
        if os.path.isfile(wheel_path):
            with open(wheel_path, encoding="utf-8", errors="replace") as f:
                tags = {line.split(":", 1)[1].strip() for line in f if line.startswith("Tag:")}
        direct = None
        direct_path = os.path.join(d, "direct_url.json")
        if os.path.isfile(direct_path):
            try:
                with open(direct_path) as f:
                    direct = json.load(f).get("url")
            except (OSError, ValueError):
                direct = "unreadable"
        out.append({"name": meta.get("Name"), "version": meta.get("Version"),
                    "wheel_tags": sorted(tags), "direct_url": direct,
                    "source": os.path.join(site_packages, entry)})
    return out


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;\\#]+)")
HASH_RE = re.compile(r"--hash[=\s]+sha256:([0-9a-fA-F]{64})")


def lock_entries(path):
    """Pinned (name, version, sha256 hashes) from requirements, uv.lock, pylock.toml,
    poetry.lock, pdm.lock or Pipfile.lock."""
    base = os.path.basename(path)
    with open(path, "rb") as f:
        raw = f.read()
    entries = []
    doc = None
    if base != "Pipfile.lock" and (base.endswith(".lock") or base.endswith(".toml")):
        try:
            doc = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            doc = None  # e.g. rye's requirements.lock is in requirements format
    if doc is not None:
        pkgs = doc.get("package") or doc.get("packages") or []
        for p in pkgs:
            hashes = []
            for art in ([p.get("sdist")] if p.get("sdist") else []) + list(p.get("wheels") or []) + list(p.get("files") or []):
                if not isinstance(art, dict):
                    continue
                h = art.get("hash") or ""
                if isinstance(art.get("hashes"), dict):
                    h = "sha256:" + art["hashes"].get("sha256", "")
                if h.startswith("sha256:") and len(h) == 71:
                    hashes.append(h[7:].lower())
            source = p.get("source") or {}
            if isinstance(source, dict) and any(k in source for k in ("editable", "directory", "path", "git", "url")):
                entries.append({"name": p.get("name"), "version": p.get("version"), "hashes": hashes,
                                "direct_url": json.dumps(source, sort_keys=True), "source": path})
                continue
            if p.get("name") and p.get("version"):
                entries.append({"name": p["name"], "version": str(p["version"]), "hashes": hashes,
                                "source": path})
        return entries
    if base == "Pipfile.lock":
        doc = json.loads(raw)
        for section in ("default", "develop"):
            for name, spec in (doc.get(section) or {}).items():
                ver = (spec.get("version") or "").lstrip("=")
                if ver:
                    hashes = [h[7:].lower() for h in spec.get("hashes", []) if h.startswith("sha256:")]
                    entries.append({"name": name, "version": ver, "hashes": hashes, "source": path})
        return entries
    # requirements format; join continuation lines first
    text = raw.decode("utf-8", errors="replace").replace("\\\n", " ")
    for line in text.splitlines():
        m = REQ_LINE.match(line)
        if m:
            entries.append({"name": m.group(1), "version": m.group(2),
                            "hashes": [h.lower() for h in HASH_RE.findall(line)], "source": path})
    return entries


# ------------------------------------------------------------------ checking

def check_one(http, dist):
    name, version = dist["name"], dist["version"]
    res = {"name": name, "version": version, "source": dist.get("source")}
    if dist.get("direct_url") and "files.pythonhosted.org" not in dist["direct_url"]:
        res.update(status="not-from-index", detail=dist["direct_url"])
        return res
    try:
        rel = release_json(http, name, version)
        if rel is None:
            res.update(status="not-on-pypi")
            return res
        files = rel.get("urls", [])
        res["metadata_repos"] = metadata_repos(rel.get("info", {}))
        # which files are "yours"
        chosen = []
        if dist.get("hashes"):
            by_hash = {f["digests"]["sha256"]: f for f in files}
            chosen = [by_hash[h] for h in dist["hashes"] if h in by_hash]
            if not chosen:
                res.update(status="hash-not-on-pypi", detail=f"{len(dist['hashes'])} hash(es)")
                return res
        elif dist.get("wheel_tags"):
            want = set(dist["wheel_tags"])
            chosen = [f for f in files if f["filename"].endswith(".whl")
                      and wheel_tags_from_filename(f["filename"]) == want]
            if not chosen:
                res.update(status="file-unknown",
                           detail="no PyPI wheel of this release has tags " + ",".join(sorted(want)))
                return res
        else:  # a bare name==version pin: look at every file of the release
            chosen = files
        res["files_checked"] = len(chosen)
        provs = {}
        for f in chosen[:8]:
            provs[f["filename"]] = fetch_provenance(http, name, version, f["filename"])
        attested = {fn: p for fn, p in provs.items() if p}
        res["files"] = sorted(provs)
        res["files_attested"] = len(attested)
        if not attested:
            res["status"] = "no-attestation"
            return res
        pubs = [pub for p in attested.values() for pub in p["publishers"]]
        uniq = {json.dumps(p, sort_keys=True) for p in pubs}
        res["publishers"] = [json.loads(u) for u in sorted(uniq)]
        res["predicate_types"] = sorted({t for p in attested.values() for t in p["predicate_types"]})
        repos = {publisher_repo(p) for p in pubs} - {None}
        if not repos:
            res["status"] = "attested-no-repo"
        elif repos & set(res["metadata_repos"]):
            res["status"] = "attested-match"
        else:
            res["status"] = "attested-other-repo"
        if len(attested) < len(provs):
            res["detail"] = f"only {len(attested)} of {len(provs)} checked files attested"
        return res
    except RuntimeError as e:
        res.update(status="error", detail=str(e))
        return res


def pin_key(r):
    return normalize(r["name"])


def pin_value(r):
    if r.get("publishers"):
        return [publisher_label(p) for p in r["publishers"]]
    return ["none"] if r["status"] == "no-attestation" else None


def main(argv=None, http=None):
    ap = argparse.ArgumentParser(
        description="Ask PyPI who published the exact files you installed or locked.",
        epilog="Exit codes: 0 ok, 1 alert, 2 usage, 3 policy failure, 4 incomplete.")
    ap.add_argument("--env", action="append", default=[], metavar="PATH",
                    help="a venv, a site-packages directory, or a directory holding them")
    ap.add_argument("--lock", action="append", default=[], metavar="FILE",
                    help="requirements.txt, uv.lock, pylock.toml, poetry.lock, pdm.lock or Pipfile.lock")
    ap.add_argument("--package", action="append", default=[], metavar="NAME==VERSION")
    ap.add_argument("--require-attestation", action="store_true",
                    help="exit 3 when any distribution has no attestation")
    ap.add_argument("--require-repo-match", action="store_true",
                    help="exit 3 unless every distribution is attested-match")
    ap.add_argument("--pins", metavar="FILE", help="alert when a publisher differs from this file")
    ap.add_argument("--write-pins", metavar="FILE", help="record the publishers seen in this run")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args(argv)

    dists = []
    for p in args.env:
        sps = find_site_packages(p)
        if not sps:
            ap.error(f"no site-packages directory under {p}")
        for sp in sps:
            dists += installed_dists(sp)
    for p in args.lock:
        dists += lock_entries(p)
    for spec in args.package:
        if "==" not in spec:
            ap.error(f"--package wants NAME==VERSION, got {spec}")
        n, v = spec.split("==", 1)
        dists.append({"name": n.strip(), "version": v.strip(), "source": "--package"})
    if not dists:
        ap.error("nothing to check: pass --env, --lock or --package")

    seen, unique = set(), []
    for d in dists:
        key = (normalize(d["name"] or ""), d["version"], tuple(d.get("hashes") or ()), tuple(d.get("wheel_tags") or ()))
        if key not in seen and d["name"] and d["version"]:
            seen.add(key)
            unique.append(d)

    http = http or Http()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda d: check_one(http, d), unique))

    alerts, policy = [], []
    pins_before = {}
    if args.pins and os.path.exists(args.pins):
        with open(args.pins) as f:
            pins_before = json.load(f)
    for r in results:
        if r["status"] in ("not-on-pypi", "hash-not-on-pypi"):
            alerts.append(r)
        old = pins_before.get(pin_key(r))
        new = pin_value(r)
        if old is not None and new is not None and old != new:
            r["pin_changed"] = {"pinned": old, "now": new}
            alerts.append(r)
        if args.require_attestation and r["status"] in ("no-attestation",):
            policy.append(r)
        if args.require_repo_match and r["status"] not in ("attested-match",):
            policy.append(r)
    if args.write_pins:
        pins = dict(pins_before)
        for r in results:
            if pin_value(r) is not None:
                pins[pin_key(r)] = pin_value(r)
        with open(args.write_pins, "w") as f:
            json.dump(pins, f, indent=1, sort_keys=True)
            f.write("\n")

    errors = [r for r in results if r["status"] == "error"]
    if args.json:
        print(json.dumps({"results": results, "requests": http.requests, "retries": http.retried},
                         indent=1))
    else:
        width = max(len(f"{r['name']}=={r['version']}") for r in results)
        for r in sorted(results, key=lambda r: normalize(r["name"])):
            line = f"{(r['name'] + '==' + r['version']).ljust(width)}  {r['status']:<19}"
            if r.get("publishers"):
                line += "  " + "; ".join(publisher_label(p) for p in r["publishers"])
            if r["status"] in ("attested-other-repo",):
                line += f"  (metadata: {', '.join(r.get('metadata_repos') or ['none'])})"
            if r.get("detail"):
                line += f"  [{r['detail']}]"
            if r.get("pin_changed"):
                line += f"  PIN CHANGED: was {r['pin_changed']['pinned']}"
            print(line)
        counts = {}
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        print("\n" + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    if alerts:
        return 1
    if errors:
        return 4
    if policy:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
