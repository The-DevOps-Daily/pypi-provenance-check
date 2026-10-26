# Sources

Read between 26 and 27 October 2026.

| Source | Used for |
|---|---|
| [BerriAI/litellm issue #47826](https://github.com/BerriAI/litellm/issues/47826) (Upwind, opened 21 Oct 2026 12:06 UTC, and the thread) | the seven wheel hashes and the sdist hash, the three payload files and their RECORD hashes, what the payload collects, host markers, exfiltration URL, dead drop, remediation order; the image digests and the image provenance naming `Berri-AI/litellm` at `20535d8f`; that 1.106.0 and 1.106.2 wheels match their tags byte for byte |
| [LiteLLM incident post](https://docs.litellm.ai/blog/security-incident-oct-21-2026) | timeline in UTC: wheels uploaded 11:39:51 to 11:40:13, PyPI removal 13:23, GHCR unavailable 13:51, Docker Hub cleaned 14:20; affected tags; what to rotate |
| [LiteLLM attack-chain post](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain) | the canonical account: master key leaked in a public repo on 27 May, used on 10 Oct; release workflows in the private `BerriAI/project-releaser`; commit `9cf97e9` pointed the release at the fork; `20535d8f` exists only on the fork; "The pipeline signed and published v1.107.0 built from the fork commit." |
| Maintainer comment of 24 Oct 2026 in issue #47826 | "there is no official v.1.107.0 source tag" |
| [JFrog: LiteLLM hijacked again](https://research.jfrog.com/post/litellm-hijacked-again/) | the sdist `pyproject.toml` change `data = "cook"`; the March 2026 compromise (1.82.7 and 1.82.8) |
| [Chainguard: LiteLLM attacked again](https://www.chainguard.dev/unchained/litellm-attacked-again-malicious-1-107-0-wheels-on-pypi-and-docker-hub-october-2026) | clean versions 1.106.2, 1.107.0rc1, 1.107.0rc2; platform image digests; March 2026 attribution to TeamPCP with a stolen PyPI token |
| [Socket: LiteLLM compromise](https://socket.dev/blog/litellm-compromise) | image provenance: builder `BerriAI/project-releaser`, dispatch input `source_owner` `Berri-AI`, `vcs:source` `https://github.com/Berri-AI/litellm`; v1.106.2 provenance records `BerriAI/litellm` |
| [PyPI attestations docs](https://docs.pypi.org/attestations/), [producing](https://docs.pypi.org/attestations/producing-attestations/), [consuming](https://docs.pypi.org/attestations/consuming-attestations/) | supported predicates (SLSA Provenance, PyPI Publish), signing identities, `pypi-attestations verify pypi --repository` |
| [pip changelog](https://pip.pypa.io/en/stable/news/) up to 26.2.2 (20 Oct 2026) | `--uploaded-prior-to` (26.0), duration form `P3D` (26.1); no option that verifies attestations |
| [uv changelog](https://github.com/astral-sh/uv/blob/main/CHANGELOG.md) up to 0.13.5 (21 Oct 2026), [uv publish guide](https://docs.astral.sh/uv/guides/package/), [settings](https://docs.astral.sh/uv/reference/settings/#exclude-newer) | `uv publish` uploads attestations but does not generate them; relative `exclude-newer`; no install-time attestation verification |
| [Docker: SLSA provenance attestations](https://docs.docker.com/build/metadata/attestations/slsa-provenance/) | `docker buildx imagetools inspect --format '{{ json .Provenance.SLSA }}'`; provenance is opt-in, `mode=min` by default |

Measured here, not taken from a source: everything under `results/` and `examples/`.
