#!/usr/bin/env python3
"""Look for the LiteLLM 1.107.0 payload without starting the suspect Python.

Run it with -I -S so the interpreter that runs this script does not process
.pth files or import sitecustomize from its own site-packages:

    python3 -I -S ioc_check.py              # default places: envs, pip/uv caches, host markers
    python3 -I -S ioc_check.py env /srv/app/.venv /usr/lib/python3
    python3 -I -S ioc_check.py lock requirements.txt uv.lock
    python3 -I -S ioc_check.py scan ~/.cache/pip ~/.cache/uv image.tar
    python3 -I -S ioc_check.py host

env   site-packages directories: litellm-1.107.0.dist-info, cook.pth, cook.py,
      their .pyc files, a sitecustomize.py or .pth with import lines that no
      installed distribution lists in its RECORD.
lock  requirements, uv.lock, pylock.toml, poetry.lock, pdm.lock, Pipfile.lock:
      a litellm 1.107.0 pin or any of the published 1.107.0 file hashes.
scan  directories or files: pip and uv caches, downloaded wheels, and image
      tarballs from `docker save`, `podman save` or `skopeo copy` (docker-archive
      or oci-archive). It reads files and tar members; it never extracts or runs them.
host  marker files in /tmp and, on Linux, processes that carry the payload's
      environment variable or hold its lock file (run as root to see all).

Exit codes: 0 nothing found, 1 indicator of the 1.107.0 payload found,
2 usage error, 3 suspicious only (needs a human look), 4 incomplete (a path
you named could not be read).

Python 3.11+ standard library. Indicators from github.com/BerriAI/litellm/issues/47826
and the LiteLLM incident reports of 21 to 23 October 2026.
"""
import argparse
import glob
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tomllib
import zipfile

VERSION = "1.107.0"
DIST_INFO = f"litellm-{VERSION}.dist-info"
DATA_DIR = f"litellm-{VERSION}.data"

# sha256 of the seven 1.107.0 wheels and the sdist (issue #47826, Chainguard, Socket)
ARTIFACT_SHA256 = {
    "7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d": "litellm-1.107.0-cp310-abi3-macosx_10_12_x86_64.whl",
    "0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a": "litellm-1.107.0-cp310-abi3-macosx_11_0_arm64.whl",
    "668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6": "litellm-1.107.0-cp310-abi3-manylinux_2_28_aarch64.whl",
    "462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7": "litellm-1.107.0-cp310-abi3-manylinux_2_28_x86_64.whl",
    "c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054": "litellm-1.107.0-cp310-abi3-musllinux_1_2_aarch64.whl",
    "1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00": "litellm-1.107.0-cp310-abi3-musllinux_1_2_x86_64.whl",
    "12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484": "litellm-1.107.0-cp310-abi3-win_amd64.whl",
    "2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819": "litellm-1.107.0.tar.gz (no payload files, tampered pyproject.toml)",
}
# sha256 of the three payload files, decoded from the wheels' RECORD entries
PAYLOAD_SHA256 = {
    "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb": "cook.pth",
    "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25": "cook.py",
    "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa": "sitecustomize.py",
}
# image index and platform manifest digests (LiteLLM incident post, Chainguard)
IMAGE_DIGESTS = {
    "1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e": "litellm / litellm/litellm v1.107.0 index",
    "bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5": "litellm v1.107.0 linux/amd64",
    "56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf": "litellm v1.107.0 linux/arm64",
    "24581ddc30767f16ecb69d2b0517556f2cd7dea56971adb42a3d1beb97d69523": "litellm-database v1.107.0 linux/amd64",
    "827dd893c74cf621a860a66a3a447a5c732533f087589ce905573e285c0a239c": "litellm-database v1.107.0 linux/arm64",
    "645a67d810628252d63df85dcc8824c58bcc77cf8383f4d3e6321f0ccc3ce9e4": "litellm-non_root v1.107.0 linux/amd64",
    "f75c8edae59b72b1ebfd617295833f465c85bb2fab9c1d60f21b496db86cb8da": "litellm-non_root v1.107.0 linux/arm64",
}
HOST_MARKERS = [
    (".pc_once_72129118c59f5636c0bb", "run-once marker: written only after a successful exfiltration POST"),
    ("remote_code_loader.lock", "lock file of the hourly remote-code loader"),
]
HOST_GLOBS = [(".pc_sq_*", "payload temp dir"), (".pc_e_*", "payload temp dir")]
# zip member names are stored uncompressed, so these bytes appear in any copy of
# the wheel, including pip's http cache entries that wrap the body
BYTE_MARKERS = [f"{DATA_DIR}/purelib/cook".encode(), f"{DATA_DIR}/purelib/sitecustomize".encode()]
SITE_DIRS = ("site-packages", "dist-packages")
SKIP_DIRS = {".git", "node_modules", "proc", "sys", "dev"}


def walk_error(rep):
    def onerror(err):
        rep.add("incomplete", "unreadable", getattr(err, "filename", "?") or "?", str(err.strerror or err))
    return onerror


class Report:
    def __init__(self):
        self.findings = []

    def add(self, severity, kind, path, detail):
        self.findings.append({"severity": severity, "kind": kind, "path": path, "detail": detail})

    def has(self, severity):
        return any(f["severity"] == severity for f in self.findings)

    def exit_code(self):
        if self.has("hit"):
            return 1
        if self.has("warn"):
            return 3
        if self.has("incomplete"):
            return 4
        return 0


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ env

def find_site_dirs(roots, rep, explicit):
    found = []
    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))
        if not os.path.exists(root):
            if explicit:
                rep.add("incomplete", "missing", root, "path does not exist")
            continue
        if os.path.basename(root) in SITE_DIRS:
            found.append(root)
            continue
        for cur, dirs, _files in os.walk(root, onerror=walk_error(rep)):
            if os.path.basename(cur) in SITE_DIRS:
                found.append(cur)
                dirs[:] = []
                continue
            if cur[len(root):].count(os.sep) >= 10:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    return sorted(set(found))


def record_owners(sp):
    """Map installed path (relative to site-packages) -> distribution, from RECORD files."""
    owners = {}
    for entry in os.listdir(sp):
        if entry.endswith(".dist-info"):
            rec = os.path.join(sp, entry, "RECORD")
            if os.path.isfile(rec):
                with open(rec, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        rel = line.split(",", 1)[0].strip()
                        if rel:
                            owners[os.path.normpath(rel)] = entry[: -len(".dist-info")]
        elif entry.endswith(".egg-info"):
            listing = os.path.join(sp, entry, "installed-files.txt")
            if os.path.isfile(listing):
                with open(listing, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        rel = os.path.normpath(os.path.join(entry, line.strip()))
                        owners[rel] = entry[: -len(".egg-info")]
    return owners


_DPKG = None


def dpkg_owner(path):
    """Debian and Ubuntu: the package whose file list names this path (read, not run)."""
    global _DPKG
    if _DPKG is None:
        _DPKG = {}
        for lst in glob.glob("/var/lib/dpkg/info/*.list"):
            pkg = os.path.basename(lst)[:-5]
            try:
                with open(lst, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.endswith((".pth\n", "sitecustomize.py\n")):
                            _DPKG[line.rstrip("\n")] = pkg
            except OSError:
                pass
    return _DPKG.get(path)


def executable_pth_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n") for ln in f if ln.startswith(("import ", "import\t"))]
    except OSError:
        return None


def check_site_dir(sp, rep):
    try:
        entries = os.listdir(sp)
    except OSError as e:
        rep.add("incomplete", "unreadable", sp, str(e))
        return
    owners = record_owners(sp)
    if DIST_INFO in entries:
        rep.add("hit", "installed", os.path.join(sp, DIST_INFO), f"litellm {VERSION} is installed")
    for e in entries:
        if e.startswith("litellm-") and e.endswith(".dist-info") and e != DIST_INFO:
            rep.add("info", "installed", os.path.join(sp, e), f"litellm {e[8:-10]} installed")
    for name in ("cook.pth", "cook.py"):
        p = os.path.join(sp, name)
        if os.path.isfile(p):
            digest = sha256_of(p)
            same = " (sha256 matches the published payload)" if digest in PAYLOAD_SHA256 else ""
            rep.add("hit", "payload-file", p, f"{name} in site-packages root{same}; owner: "
                    f"{owners.get(name, 'no RECORD lists it')}")
    pyc_dir = os.path.join(sp, "__pycache__")
    if os.path.isdir(pyc_dir):
        for e in os.listdir(pyc_dir):
            if e.startswith("cook.") and e.endswith(".pyc"):
                rep.add("hit", "payload-file", os.path.join(pyc_dir, e), "compiled cook module")
    sc = os.path.join(sp, "sitecustomize.py")
    if os.path.isfile(sc):
        digest = sha256_of(sc)
        owner = owners.get("sitecustomize.py")
        if digest in PAYLOAD_SHA256:
            rep.add("hit", "payload-file", sc, "sitecustomize.py matches the published payload sha256")
        elif owner and owner.startswith(f"litellm-{VERSION}"):
            rep.add("hit", "payload-file", sc, f"sitecustomize.py installed by {owner}")
        elif owner:
            rep.add("info", "sitecustomize", sc, f"sitecustomize.py owned by {owner}")
        elif dpkg_owner(sc):
            rep.add("info", "sitecustomize", sc, f"sitecustomize.py from the {dpkg_owner(sc)} system package")
        else:
            rep.add("warn", "sitecustomize", sc,
                    "sitecustomize.py that no installed distribution lists in its RECORD")
    for e in entries:
        if not e.endswith(".pth") or e == "cook.pth":
            continue
        p = os.path.join(sp, e)
        lines = executable_pth_lines(p)
        if not lines:
            continue
        owner = owners.get(e)
        deb = None if owner else dpkg_owner(p)
        if owner:
            rep.add("info", "pth-import", p, f"runs at startup, owned by {owner}: {lines[0][:80]}")
        elif deb:
            rep.add("info", "pth-import", p, f"runs at startup, installed by the {deb} system package")
        elif e == "_virtualenv.pth" and os.path.isfile(os.path.join(sp, "_virtualenv.py")):
            rep.add("info", "pth-import", p, "virtualenv's own startup hook")
        else:
            rep.add("warn", "pth-import", p, f"runs at startup, no RECORD lists it: {lines[0][:80]}")


def default_env_roots():
    home = os.path.expanduser("~")
    roots = ["/usr/lib", "/usr/local/lib", "/opt", "/srv", "/app", home]
    if sys.platform == "darwin":
        roots += ["/Library/Frameworks/Python.framework", "/opt/homebrew/lib"]
    return roots


# ------------------------------------------------------------------ lock

REQ_LINE = re.compile(r"^\s*litellm(?:\[[^\]]*\])?\s*(===|==)\s*([^\s;#\\,]+)", re.I | re.M)
REQ_ANY = re.compile(r"^\s*litellm(?:\[[^\]]*\])?\s*(?:[;#\\]|$|[<>!~=])", re.I | re.M)
RELEASE_ONLY = re.compile(r"^v?(\d+(?:\.\d+)*)$", re.I)


def is_bad_version(op, ver):
    """True if `op ver` selects exactly the 1.107.0 release (PEP 440 zero padding:
    ==1.107 and ==1.107.0.0 are the same version). === compares strings."""
    ver = ver.strip().lower()
    if op == "===":
        return ver == VERSION
    if ver.endswith(".*"):
        return False  # a prefix match is a range; reported as unpinned
    m = RELEASE_ONLY.match(ver)
    if not m:
        return False  # pre, post, dev or local releases are other versions
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return parts == [1, 107]


def check_lock(path, rep):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        rep.add("incomplete", "unreadable", path, str(e))
        return
    text = raw.decode("utf-8", errors="replace")
    lowered = text.lower()
    for digest, what in ARTIFACT_SHA256.items():
        if digest in lowered:
            rep.add("hit", "lock-hash", path, f"contains the sha256 of {what}")
    pinned = False
    doc = None
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
    if isinstance(doc, dict):
        for key in ("package", "packages"):
            for p in doc.get(key) or []:
                if isinstance(p, dict) and str(p.get("name", "")).lower() == "litellm" \
                        and is_bad_version("==", str(p.get("version", ""))):
                    pinned = True
        for section in ("default", "develop"):
            spec = (doc.get(section) or {}).get("litellm") if isinstance(doc.get(section), dict) else None
            if isinstance(spec, dict) and is_bad_version("==", spec.get("version", "").lstrip("=")):
                pinned = True
    if any(is_bad_version(op, ver) for op, ver in REQ_LINE.findall(text)):
        pinned = True
    if pinned:
        rep.add("hit", "lock-pin", path, f"pins litellm {VERSION}")
    elif REQ_ANY.search(text):
        rep.add("info", "lock-unpinned", path,
                "litellm without an exact pin: check what resolved on 21 Oct 2026, 11:39 to 13:23 UTC")


# ------------------------------------------------------------------ scan

def tar_member_hits(names, where, rep):
    for n in names:
        norm = n.lstrip("./")
        base = os.path.basename(norm)
        parent = os.path.basename(os.path.dirname(norm))
        if f"/{DIST_INFO}/" in f"/{norm}/" or f"/{DATA_DIR}/" in f"/{norm}/":
            rep.add("hit", "image-layer", where, f"contains {norm}")
        elif parent in SITE_DIRS and base in ("cook.pth", "cook.py"):
            rep.add("hit", "image-layer", where, f"contains {norm}")
        elif parent in SITE_DIRS and base == "sitecustomize.py":
            rep.add("warn", "image-layer", where, f"contains {norm} (check which package owns it)")
        for digest, what in IMAGE_DIGESTS.items():
            if digest in norm:
                rep.add("hit", "image-digest", where, f"blob {digest[:12]}: {what}")


def scan_tar(fileobj_or_path, where, rep, depth=0):
    try:
        if isinstance(fileobj_or_path, str):
            tf = tarfile.open(fileobj_or_path, mode="r:*")
        else:
            tf = tarfile.open(fileobj=fileobj_or_path, mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as e:
        rep.add("incomplete", "unreadable-archive", where, f"looks like an archive but could not be read: {e}")
        return
    with tf:
        members = tf.getmembers()
        tar_member_hits([m.name for m in members], where, rep)
        for m in members:
            if m.name.endswith(("index.json", "manifest.json")) and m.isfile() and m.size < 1 << 20:
                body = tf.extractfile(m).read().decode("utf-8", errors="replace")
                for digest, what in IMAGE_DIGESTS.items():
                    if digest in body:
                        rep.add("hit", "image-digest", f"{where}!{m.name}", what)
            if depth >= 2 or not m.isfile() or m.size < 20:
                continue
            f = tf.extractfile(m)
            head = f.read(512)
            f.seek(0)
            if head[:2] == b"\x1f\x8b" or head[257:262] == b"ustar":
                scan_tar(f, f"{where}!{m.name}", rep, depth + 1)
            elif head[:4] == b"\x28\xb5\x2f\xfd":
                rep.add("incomplete", "zstd-layer", f"{where}!{m.name}",
                        "zstd-compressed layer: this Python cannot read it")
            elif head[:4] == b"PK\x03\x04":
                scan_zip(io.BytesIO(f.read()), f"{where}!{m.name}", rep)


def scan_zip(fileobj_or_path, where, rep):
    try:
        with zipfile.ZipFile(fileobj_or_path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return
    bad = [n for n in names if n.startswith((f"{DIST_INFO}/", f"{DATA_DIR}/"))
           and ("/purelib/" in n or n.endswith("/METADATA"))]
    if bad:
        rep.add("hit", "wheel", where, "contains " + ", ".join(sorted(bad)))
        return
    for n in names:
        if re.match(r"[^/]+\.data/purelib/sitecustomize\.py$", n):
            rep.add("warn", "wheel", where, f"wheel installs {n} into site-packages root")


def scan_file(path, rep, max_size):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError as e:
        rep.add("incomplete", "unreadable", path, str(e))
        return
    is_zip = head[:4] == b"PK\x03\x04"
    is_tar = head[:2] == b"\x1f\x8b" or head[257:262] == b"ustar"
    if size <= max_size:
        # one pass: the file's sha256 (a wheel or the sdist itself, or pip's http-v2
        # .body copy) and the payload's member names (pip's older http cache wraps
        # the wheel in a response record; zip member names are stored uncompressed)
        h = hashlib.sha256()
        tail, marker = b"", None
        keep = max(len(m) for m in BYTE_MARKERS)
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
                    if marker is None:
                        buf = tail + chunk
                        marker = next((m for m in BYTE_MARKERS if m in buf), None)
                        tail = buf[-keep:]
        except OSError as e:
            rep.add("incomplete", "unreadable", path, str(e))
            return
        digest = h.hexdigest()
        if digest in ARTIFACT_SHA256:
            rep.add("hit", "artifact-hash", path, f"sha256 is {ARTIFACT_SHA256[digest]}")
        if marker and not is_zip:
            rep.add("hit", "cache-entry", path, f"contains the member name {marker.decode()}")
    if is_zip:
        scan_zip(path, path, rep)
    elif is_tar:
        scan_tar(path, path, rep)


def scan_path(root, rep, max_size, explicit=True):
    root = os.path.abspath(os.path.expanduser(root))
    if not os.path.exists(root):
        if explicit:
            rep.add("incomplete", "missing", root, "path does not exist")
        return
    if os.path.isfile(root):
        scan_file(root, rep, max_size)
        return
    for cur, dirs, files in os.walk(root, onerror=walk_error(rep)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for d in list(dirs):
            if d in (DIST_INFO, DATA_DIR):
                rep.add("hit", "unpacked", os.path.join(cur, d), "unpacked litellm 1.107.0 wheel (uv archive or similar)")
                dirs.remove(d)
        if os.path.basename(cur) == "litellm":
            for fn in files + dirs:
                if fn.startswith(f"{VERSION}-") or fn == VERSION:
                    rep.add("hit", "cache-index", os.path.join(cur, fn), "uv cache entry for litellm 1.107.0")
        for fn in files:
            p = os.path.join(cur, fn)
            if os.path.islink(p):
                continue
            if fn in ("cook.pth", "cook.py") and os.path.basename(cur) in SITE_DIRS + ("purelib",):
                rep.add("hit", "payload-file", p, f"{fn} next to installed packages")
            scan_file(p, rep, max_size)


def default_cache_roots():
    home = os.path.expanduser("~")
    roots = [os.environ.get("PIP_CACHE_DIR"), os.environ.get("UV_CACHE_DIR"),
             os.environ.get("XDG_CACHE_HOME") and os.path.join(os.environ["XDG_CACHE_HOME"], "pip"),
             os.environ.get("XDG_CACHE_HOME") and os.path.join(os.environ["XDG_CACHE_HOME"], "uv"),
             os.path.join(home, ".cache", "pip"), os.path.join(home, ".cache", "uv"),
             os.path.join(home, "Library", "Caches", "pip"), os.path.join(home, "Library", "Caches", "uv"),
             os.path.join(home, ".cache", "pypoetry"), os.path.join(home, ".cache", "pdm")]
    return [r for r in dict.fromkeys(roots) if r]


# ------------------------------------------------------------------ host

def check_host(rep, tmp_dir="/tmp", proc_dir="/proc"):
    for name, what in HOST_MARKERS:
        p = os.path.join(tmp_dir, name)
        if os.path.exists(p):
            rep.add("hit", "host-marker", p, what)
    for pattern, what in HOST_GLOBS:
        for p in glob.glob(os.path.join(tmp_dir, pattern)):
            rep.add("hit", "host-marker", p, what)
    if not os.path.isdir(proc_dir):
        return
    lock = os.path.join(tmp_dir, "remote_code_loader.lock")
    unreadable = 0
    for pid in os.listdir(proc_dir):
        if not pid.isdigit():
            continue
        base = os.path.join(proc_dir, pid)
        try:
            with open(os.path.join(base, "environ"), "rb") as f:
                env = f.read()
        except OSError:
            unreadable += 1
            continue
        if b"PRIVCOLLECT_ACTIVE=1" in env.split(b"\0"):
            rep.add("hit", "process", base, "process environment has PRIVCOLLECT_ACTIVE=1")
        try:
            for fd in os.listdir(os.path.join(base, "fd")):
                if os.readlink(os.path.join(base, "fd", fd)) == lock:
                    rep.add("hit", "process", base, f"process holds {lock}")
                    break
        except OSError:
            pass
    if unreadable:
        rep.add("info", "process", proc_dir,
                f"{unreadable} processes not readable as this user; run as root to check them")


# ------------------------------------------------------------------ main

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Look for the LiteLLM 1.107.0 payload without starting the suspect Python.",
        epilog="Exit codes: 0 nothing found, 1 indicator found, 2 usage, 3 suspicious, 4 incomplete.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-size", type=int, default=1 << 30,
                    help="byte-search files up to this size (default 1 GiB)")
    ap.add_argument("--tmp-dir", default="/tmp", help=argparse.SUPPRESS)
    ap.add_argument("--proc-dir", default="/proc", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd")
    for name in ("env", "lock", "scan"):
        sp = sub.add_parser(name)
        sp.add_argument("paths", nargs="+" if name == "lock" else "*")
    sub.add_parser("host")
    sub.add_parser("all")
    args = ap.parse_args(argv)
    cmd = args.cmd or "all"

    rep = Report()
    if not sys.flags.no_site:
        rep.add("info", "interpreter", sys.executable,
                "run with python3 -I -S so this interpreter skips .pth files and sitecustomize")
    if cmd in ("env", "all"):
        roots = getattr(args, "paths", None) or default_env_roots()
        sites = find_site_dirs(roots, rep, explicit=bool(getattr(args, "paths", None)))
        for sp in sites:
            check_site_dir(sp, rep)
        rep.add("info", "searched", ", ".join(roots), f"{len(sites)} site-packages directories checked")
    if cmd == "lock":
        for p in args.paths:
            check_lock(p, rep)
    if cmd in ("scan", "all"):
        roots = getattr(args, "paths", None) or default_cache_roots()
        for r in roots:
            scan_path(r, rep, args.max_size, explicit=bool(getattr(args, "paths", None)))
        rep.add("info", "searched", ", ".join(roots), "scanned")
    if cmd in ("host", "all"):
        check_host(rep, args.tmp_dir, args.proc_dir)

    code = rep.exit_code()
    if args.json:
        print(json.dumps({"exit_code": code, "findings": rep.findings}, indent=1))
    else:
        order = {"hit": 0, "warn": 1, "incomplete": 2, "info": 3}
        for f in sorted(rep.findings, key=lambda f: order[f["severity"]]):
            print(f"{f['severity'].upper():<10} {f['kind']:<16} {f['path']}\n{'':<27}{f['detail']}")
        verdict = {0: "no indicator of the litellm 1.107.0 payload found",
                   1: "INDICATORS FOUND: treat this host as compromised and rotate what it could reach",
                   3: "nothing matched the payload, but something above needs a human look",
                   4: "incomplete: a path you named could not be read"}[code]
        print(f"\n{verdict} (exit {code})")
    return code


if __name__ == "__main__":
    sys.exit(main())
