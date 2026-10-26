# pypi-provenance-check

```bash
python3 -I -S ioc_check.py                               # litellm 1.107.0 payload: envs, pip/uv caches, host markers
python3 -I -S ioc_check.py lock requirements.txt uv.lock  # a 1.107.0 pin or file hash in your locks
python3 -I -S ioc_check.py scan image.tar                 # a `docker save` / `podman save` / `docker export` tarball
python3 -I -S provenance_check.py --env .venv            # who published the PyPI files you installed
python3 -I -S provenance_check.py --lock uv.lock --require-attestation
```

Two checks that came out of the LiteLLM 1.107.0 compromise of 21 October 2026, and the survey behind the post [LiteLLM 1.107.0 was built from a lookalike fork: what PyPI provenance can and cannot tell you](https://devops-daily.com/posts/litellm-1-107-0-compromise-pypi-provenance).

LiteLLM 1.107.0 was built by the project's own release pipeline from a lookalike fork (`Berri-AI/litellm`), so reading `github.com/BerriAI/litellm` showed nothing wrong. The question this repo measures: which record would have named the fork, and how many PyPI projects publish the record a provenance check needs.

Python 3.11+ standard library only. Nothing here downloads or runs the malicious release. The IOC tests use harmless fixtures built at test time (`tests/fixtures.py`).

## ioc_check.py

Run it with `-I -S`. The payload runs whenever a Python interpreter starts with the infected site-packages on its path, and `-S` stops the interpreter that runs this script from processing `.pth` files or importing `sitecustomize`. It reads files only.

| Command | What it looks for |
|---|---|
| `env [PATH...]` | `litellm-1.107.0.dist-info`, `cook.pth`, `cook.py`, `__pycache__/cook*.pyc` in any site-packages under PATH; a `sitecustomize.py` or a `.pth` with `import` lines that no installed distribution lists in its RECORD (and, on Debian and Ubuntu, that no system package installed) |
| `lock FILE...` | a pin that selects 1.107.0 (`==1.107.0`, and equivalent spellings such as `==1.107` or `==1.107.0.0`; `===1.107.0` as a string) in requirements, uv.lock, pylock.toml, poetry.lock, pdm.lock or Pipfile.lock, or any of the eight published 1.107.0 file hashes in any text file |
| `scan PATH...` | pip's `http` and `http-v2` caches, uv's `archive-v0` and `wheels-v*` entries, any file whose sha256 is one of the seven wheels or the sdist, wheel member names, and image tarballs: `docker save`, OCI archives with gzip layers, and flat `docker export` tars |
| `host` | `/tmp/.pc_once_72129118c59f5636c0bb` (written only after a successful exfiltration), `/tmp/remote_code_loader.lock`, `/tmp/.pc_sq_*`, `/tmp/.pc_e_*`; on Linux, processes with `PRIVCOLLECT_ACTIVE=1` or holding the lock (run as root to see every process) |
| no command | `env` on `/usr/lib`, `/usr/local/lib`, `/opt`, `/srv`, `/app` and your home directory, `scan` on the pip, uv, poetry and pdm caches, and `host` |

Exit codes: `0` nothing found, `1` an indicator of the 1.107.0 payload, `2` usage error, `3` something suspicious that is not the payload (needs a human look), `4` incomplete: a path, directory or archive could not be read.

It does not read zstd-compressed image layers (reported as incomplete), registries, Windows hosts, or network logs. For network logs, search DNS and proxy logs for `www.litellm.dev` and `raw.githubusercontent.com/letters9813/pythonclient-test`.

To check an image without starting Python inside it:

```bash
docker save litellm/litellm:main-stable -o img.tar && python3 -I -S ioc_check.py scan img.tar
docker export "$(docker create litellm/litellm:main-stable)" -o fs.tar && python3 -I -S ioc_check.py scan fs.tar
```

On a Debian 12 based machine, `/usr/lib/python3/dist-packages` holds `.pth` files with `import` lines that no RECORD lists. The checker reads dpkg's file lists (`/var/lib/dpkg/info/*.list`) to see that system packages installed them, so they are reported as info, not as suspicious (`examples/debian-dist-packages.txt`).

`scripts/cache_layout_demo.sh` puts the fixture wheel through uv 0.13.0, pip 23.0.1 and pip 26.2.2 and runs the scan on what each left behind (`examples/cache-layout-demo.txt`). `scripts/fixture_demo.sh` runs the env and image checks on the fixtures (`examples/ioc-check-fixtures.txt`).

## provenance_check.py

Run it with `-I -S` too. For each distribution in a venv, a lock file or a `--package NAME==VERSION`, it finds the PyPI files you use: every hash in a lock must match a file of that release, and an installed wheel is matched by the tags in its `.dist-info/WHEEL` and checked by the sha256 of its `METADATA`, which pip and uv install unchanged and PyPI publishes for each wheel. That ties an installed wheel to a PyPI wheel's metadata, not to every installed byte. It then asks PyPI which of those files have provenance (Simple JSON API), reads the provenance of every one that has it (Integrity API), and reports the Trusted Publishers (repository, workflow, environment) and whether their repositories are ones the release's metadata names.

Statuses: `attested-match`, `attested-other-repo`, `attested-no-repo` (a Google Cloud service account), `partly-attested`, `no-attestation`, `not-on-pypi` (removed or never published: this is how a 1.107.0 install shows up today), `hash-not-on-pypi`, `metadata-differs`, `not-from-index`, `file-unknown`, `error`.

- `--write-pins pins.json` records each project's publishers; `--pins pins.json` alerts when they change, disappear, or cannot be confirmed in this run (the pins file must exist). Pin the publisher you observed, not the repository in the metadata: numpy, scipy, scikit-learn, matplotlib and litellm all publish from a separate release repository on purpose.
- `--require-attestation` (anything that is not `attested-*`) and `--require-repo-match` (anything that is not `attested-match`) turn gaps into exit code 3.

Exit codes: `0` ok, `1` alert (`not-on-pypi`, `hash-not-on-pypi`, `metadata-differs`, or a pinned project whose publishers changed or could not be confirmed), `2` usage, `3` policy failure, `4` network errors.

It reads PyPI's record. PyPI checks each attestation's signature at upload; this script does not repeat the Sigstore verification. To verify a file yourself, use `pypi-attestations verify pypi --repository <url> pypi:<file>` (`scripts/verify_with_pypi_attestations.sh`). It does not resolve renamed repositories; the survey does.

## The survey

```bash
python3 -I survey/snapshot_top.py --top 1000            # fixed input: data/top-pypi-packages-2026-10-01-top1000.json
python3 -I survey/survey.py --top data/top-pypi-packages-2026-10-01-top1000.json --extra survey/ai-packages.txt
GITHUB_TOKEN=... python3 -I survey/resolve_repos.py results/survey-<run>.json
python3 -I survey/summarize.py results/survey-<run>.json
python3 -I scripts/spot_check.py results/survey-<run>.json   # method check, other API path
```

The set: the 1,000 most downloaded projects in the 30 days before 1 October 2026 ([hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages), saved in `data/`), plus 44 AI-stack projects in `survey/ai-packages.txt` (22 of them are not in the top 1,000). For each project: the latest release as PyPI reports it, how many of its files have provenance (Simple JSON API), and the publisher of up to three of them (Integrity API). `resolve_repos.py` asks GitHub for the canonical name of every repository on either side of a mismatch, so a renamed or transferred repository counts as a match.

## Results

Survey run `results/survey-20261026T223625Z.json`, 26 October 2026, 22:36 UTC, 1,022 projects, no errors, no retries. Summary: `results/summary-20261026T223625Z.md`.

| Group | Projects | Latest release attested | Attested by the repo the metadata names |
|---|---|---|---|
| Top 1-1000 | 1,000 | 390 (39.0%) | 334 (33.4%) |
| Top 1-100 | 100 | 60 (60.0%) | 56 (56.0%) |
| Top 101-500 | 400 | 162 (40.5%) | 140 (35.0%) |
| Top 501-1000 | 500 | 168 (33.6%) | 138 (27.6%) |
| Top 1-1000, latest uploaded on or after 14 Nov 2024 | 864 | 389 (45.0%) | 333 (38.5%) |
| AI-stack list | 44 | 13 (29.5%) | 11 (25.0%) |

- Of the 390 attested top-1,000 projects, 30 are attested by a Google Cloud service account (no repository), 19 by a different repository than the metadata names (for 14 of those projects the publishing repository is not publicly visible), and 7 have no GitHub or GitLab URL in their metadata.
- 23 projects attested an earlier release and not their latest one (22 in the top 1,000, plus dspy). litellm is one of them.
- `results/regression-workflows.txt` reads the publish workflows of those 23 projects as they are today: 12 upload with `uv publish`, which uploads attestations but does not create them; 2 (langchain-core, dspy) set `attestations: false` on the PyPA publish action; for 7 no upload step was found in a public workflow; 2 (databricks-sdk, rich-toolkit) name no GitHub repository in their metadata, so nothing was read. Several packages share one repository (typer and typer-slim, httpx2 and httpcore2, the Supabase family), so this is repository-level evidence. It shows how they publish now, not why the attestations stopped.
- Every attestation in the sampled files (up to three per latest release) was a PyPI publish attestation (`https://docs.pypi.org/attestations/publish/v1`). No SLSA provenance attestation, the PyPI type that can record a source repository, was seen on any of the 396 attested projects.
- Method check: `results/spot-check-20261026T223625Z.txt` re-asked the Integrity API file by file (up to 80 files per release) for 40 random projects and the 23 above. 63 of 63 agree with the survey.
- The survey file is stamped with the sha256 of `survey/survey.py` and `provenance_check.py` at the first commit (`4c09da4`). Later commits changed only the docstring, the imports, `installed_dists`, `check_one` and `main` in `provenance_check.py`, and added `provenance_presence`; the survey calls none of them.

litellm (`results/litellm-attestation-history.txt`, `examples/pypi-attestations-verify.txt`, `examples/image-provenance.txt`, `results/image-provenance-20261026T225151Z.json`):

- 956 releases on PyPI. 15 carry attestations: 1.83.0 to 1.83.14, 31 March to 26 April 2026. None of the 214 releases since (1.84.0.dev1 on 29 April to 1.106.4 on 25 October) do, including 1.106.2, built by the same pipeline an hour before 1.107.0.
- All 15 (one attested file read per release) name the publisher `BerriAI/project-releaser`, workflow `publish-litellm.yml`, environment `pypi-publish`. `pypi-attestations verify pypi --repository https://github.com/BerriAI/litellm` fails on 1.83.14; with `--repository https://github.com/BerriAI/project-releaser` it passes.
- The BuildKit provenance on the v1.106.2 images (GHCR and Docker Hub, 3 variants, 2 platforms) records `vcs:source https://github.com/BerriAI/litellm` at `49943cd`, the v1.106.2 tag. The 1.107.0 images return 404 by tag and by digest; the researchers who read their provenance before removal recorded `https://github.com/Berri-AI/litellm` at `20535d8f`.

`examples/provenance-check-litellm-1.106.2-lock.txt`: litellm 1.106.2 and its 57 dependencies, hash-locked for Linux x86_64 and Python 3.12 (every hashed file checked): 33 attested by the repository their metadata names, 1 by a renamed one (filelock), 24 not attested, litellm among them.

## Files

| Path | What it is |
|---|---|
| `CLAIM.md` | the claim, written before the survey, and what would disprove it |
| `SOURCES.md` | incident sources and what each one says |
| `data/` | the fixed top-1,000 snapshot |
| `results/` | survey run, repo resolution, summary, spot check, litellm history, image provenance, tag list, publish steps of the projects that stopped attesting |
| `examples/` | recorded runs of the scripts |
| `scripts/` | `image_provenance.py` (BuildKit provenance from a registry, no layers, `--json` for the full record), `litellm_history.py`, `litellm_tags.sh`, `regression_workflows.py`, `spot_check.py`, `verify_with_pypi_attestations.sh`, and the two demos |
| `tests/` | `python3 -I -S -m unittest discover -s tests` (55 tests, offline) |

MIT license.
