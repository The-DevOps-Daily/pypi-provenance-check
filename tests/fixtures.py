"""Harmless stand-ins for the LiteLLM 1.107.0 artifacts, built at test time.

Nothing here is the real payload. The fake cook.py and sitecustomize.py hold a
single comment. cook.pth holds `import cook`, which is byte-identical to the
real 12-byte cook.pth (its sha256 is the one published in the wheel RECORD):
that file only imports cook.py, and here cook.py is empty.

    python3 -I tests/fixtures.py OUT_DIR    # write every fixture to OUT_DIR
"""
import base64
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import zipfile

NAME, VERSION = "litellm", "1.107.0"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
DATA = f"{NAME}-{VERSION}.data/purelib"
PAYLOAD = {
    "cook.pth": b"import cook\n",
    "cook.py": b"# harmless test fixture standing in for cook.py, which is a credential stealer\n",
    "sitecustomize.py": b"# harmless test fixture standing in for the remote-code loader\n",
}


def _record_line(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}"


def wheel_members(name=NAME, version=VERSION, payload=True):
    dist_info = f"{name}-{version}.dist-info"
    files = {f"{name}/__init__.py": b"# harmless fixture package\n"}
    if payload:
        for fn, data in PAYLOAD.items():
            files[f"{name}-{version}.data/purelib/{fn}"] = data
    files[f"{dist_info}/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        f"Project-URL: Repository, https://github.com/BerriAI/litellm\n").encode()
    files[f"{dist_info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: fixtures\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = [_record_line(p, d) for p, d in files.items()] + [f"{dist_info}/RECORD,,"]
    files[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode()
    return files


def build_wheel(out_dir, **kw):
    files = wheel_members(**kw)
    name = kw.get("name", NAME)
    version = kw.get("version", VERSION)
    path = os.path.join(out_dir, f"{name}-{version}-py3-none-any.whl")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for p, d in files.items():
            z.writestr(p, d)
    return path


def install_like_pip(site_packages, **kw):
    """Unpack a fixture wheel the way an installer does: .data/purelib goes to the root,
    and RECORD lists the installed paths."""
    os.makedirs(site_packages, exist_ok=True)
    files = wheel_members(**kw)
    name = kw.get("name", NAME)
    version = kw.get("version", VERSION)
    dist_info = f"{name}-{version}.dist-info"
    prefix = f"{name}-{version}.data/purelib/"
    installed = {}
    for p, d in files.items():
        if p.endswith("/RECORD"):
            continue
        installed[p[len(prefix):] if p.startswith(prefix) else p] = d
    record = [_record_line(p, d) for p, d in installed.items()] + [f"{dist_info}/RECORD,,"]
    installed[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode()
    for p, d in installed.items():
        full = os.path.join(site_packages, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(d)
    return site_packages


def _tar_bytes(files, gz=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for p, d in files.items():
            info = tarfile.TarInfo(p)
            info.size = len(d)
            tf.addfile(info, io.BytesIO(d))
    raw = buf.getvalue()
    return gzip.compress(raw) if gz else raw


def layer_files(infected=True):
    sp = "app/.venv/lib/python3.13/site-packages"
    files = {f"{sp}/requests/__init__.py": b"# fixture\n"}
    if infected:
        files.update({f"{sp}/{fn}": d for fn, d in PAYLOAD.items()})
        files[f"{sp}/{DIST_INFO}/METADATA"] = f"Name: {NAME}\nVersion: {VERSION}\n".encode()
    return files


def build_docker_save(path, infected=True):
    """Classic `docker save` layout: manifest.json plus <id>/layer.tar."""
    layer = _tar_bytes(layer_files(infected))
    files = {
        "manifest.json": json.dumps([{"Config": "cfg.json", "RepoTags": ["fixture:latest"],
                                      "Layers": ["abc123/layer.tar"]}]).encode(),
        "cfg.json": b"{}",
        "abc123/layer.tar": layer,
    }
    with open(path, "wb") as f:
        f.write(_tar_bytes(files))
    return path


def build_oci_archive(path, infected=True):
    """OCI image layout in a tar, gzip layers, as `podman save --format oci-archive` writes."""
    layer = _tar_bytes(layer_files(infected), gz=True)
    ldig = hashlib.sha256(layer).hexdigest()
    config = b"{}"
    cdig = hashlib.sha256(config).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": f"sha256:{cdig}"},
                           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                                       "digest": f"sha256:{ldig}"}]}).encode()
    mdig = hashlib.sha256(manifest).hexdigest()
    files = {
        "oci-layout": b'{"imageLayoutVersion": "1.0.0"}',
        "index.json": json.dumps({"schemaVersion": 2, "manifests": [{"digest": f"sha256:{mdig}"}]}).encode(),
        f"blobs/sha256/{mdig}": manifest,
        f"blobs/sha256/{cdig}": config,
        f"blobs/sha256/{ldig}": layer,
    }
    with open(path, "wb") as f:
        f.write(_tar_bytes(files))
    return path


def write_all(out):
    os.makedirs(out, exist_ok=True)
    build_wheel(out)
    install_like_pip(os.path.join(out, "infected-venv/lib/python3.12/site-packages"))
    install_like_pip(os.path.join(out, "clean-venv/lib/python3.12/site-packages"),
                     version="1.106.2", payload=False)
    build_docker_save(os.path.join(out, "image-docker-save.tar"))
    build_oci_archive(os.path.join(out, "image-oci.tar"))
    build_oci_archive(os.path.join(out, "image-oci-clean.tar"), infected=False)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fixtures.py OUT_DIR")
    write_all(sys.argv[1])
    print(f"fixtures written to {sys.argv[1]}")
