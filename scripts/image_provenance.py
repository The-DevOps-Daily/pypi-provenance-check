#!/usr/bin/env python3
"""Read the BuildKit provenance attached to a container image, without pulling layers.

    python3 -I scripts/image_provenance.py ghcr.io/berriai/litellm:v1.106.2 [more refs...]

For each reference it fetches the image index (a few KB of JSON), finds the
attestation manifests BuildKit attaches (vnd.docker.reference.type =
attestation-manifest), downloads only the in-toto provenance blob, checks it
against its digest, and prints where BuildKit says the build came from:
vcs:source, vcs:revision, the builder (CI run) and the workflow. It never
downloads an image layer. Anonymous tokens only, so it works for public GHCR and
Docker Hub images. A reference can be a tag or a sha256 digest.

This provenance is written by the build that produced the image. It records the
git remote of the build context; whoever controls the build can change it. It
is evidence, not a signature.
"""
import hashlib
import json
import sys
import urllib.error
import urllib.request

ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json"])


def parse_ref(ref):
    if "@" in ref:
        name, tag = ref.split("@", 1)
    else:
        name, _, tag = ref.rpartition(":")
    registry, _, repo = name.partition("/")
    if registry == "docker.io":
        registry = "registry-1.docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return registry, repo, tag


def token_for(registry, repo):
    if registry == "ghcr.io":
        url = f"https://ghcr.io/token?scope=repository:{repo}:pull"
    else:
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    with urllib.request.urlopen(url, timeout=30) as r:
        doc = json.load(r)
    return doc.get("token") or doc.get("access_token")


def get(registry, repo, path, token, accept=ACCEPT):
    req = urllib.request.Request(f"https://{registry}/v2/{repo}/{path}", headers={
        "Authorization": f"Bearer {token}", "Accept": accept, "User-Agent": "pypi-provenance-check/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def inspect(ref):
    registry, repo, tag = parse_ref(ref)
    token = token_for(registry, repo)
    try:
        raw = get(registry, repo, f"manifests/{tag}", token)
    except urllib.error.HTTPError as e:
        return {"ref": ref, "status": f"HTTP {e.code}"}
    index = json.loads(raw)
    out = {"ref": ref, "status": "ok", "index_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
           "platforms": []}
    by_digest = {m["digest"]: m for m in index.get("manifests", [])}
    for m in index.get("manifests", []):
        ann = m.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        subject = by_digest.get(ann.get("vnd.docker.reference.digest"), {})
        plat = subject.get("platform", {})
        att = json.loads(get(registry, repo, f"manifests/{m['digest']}", token))
        for layer in att.get("layers", []):
            if "slsa.dev/provenance" not in (layer.get("annotations") or {}).get("in-toto.io/predicate-type", ""):
                continue
            blob = get(registry, repo, f"blobs/{layer['digest']}", token, accept="*/*")
            assert "sha256:" + hashlib.sha256(blob).hexdigest() == layer["digest"], "blob digest mismatch"
            stmt = json.loads(blob)
            pred = stmt["predicate"]
            bd = pred.get("buildDefinition", {})
            ip = bd.get("internalParameters", {})
            vcs = pred.get("runDetails", {}).get("metadata", {}).get("buildkit_metadata", {}).get("vcs", {})
            out["platforms"].append({
                "platform": f"{plat.get('os')}/{plat.get('architecture')}",
                "manifest_digest": subject.get("digest"),
                "provenance_blob": layer["digest"],
                "predicate_type": stmt.get("predicateType"),
                "vcs_source": vcs.get("source"),
                "vcs_revision": vcs.get("revision"),
                "builder": pred.get("runDetails", {}).get("builder", {}).get("id"),
                "workflow_ref": ip.get("github_workflow_ref"),
                "workflow_sha": ip.get("github_workflow_sha"),
                "event": ip.get("github_event_name"),
                "dispatch_inputs": (ip.get("github_event_payload") or {}).get("inputs"),
                "started": pred.get("runDetails", {}).get("metadata", {}).get("startedOn"),
            })
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    results = [inspect(ref) for ref in sys.argv[1:]]
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
