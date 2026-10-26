# Claim

Written on 27 October 2026, before the survey ran.

LiteLLM 1.107.0 got past anyone who reviewed `github.com/BerriAI/litellm`, because it was not built from that repository. The one record that named the lookalike fork was the Docker image's BuildKit provenance. A PyPI attestation would not have named it: a PyPI publish attestation identifies the workflow that uploaded the file, litellm uploads from a separate private release repository that the attacker drove, and litellm had stopped publishing attestations in April 2026. Across the most downloaded PyPI projects, only a minority of latest releases carry an attestation, and fewer carry one that names the repository in the project's own metadata.

## What would prove it wrong

- litellm's attestations name `BerriAI/litellm` as the publisher repository (then a repository check would have flagged a fork build).
- litellm 1.106.x, built by the same pipeline an hour before 1.107.0, has attestations (then 1.107.0 would have had one too, and its absence or content would be a signal).
- Most of the surveyed latest releases carry an attestation that names the repository in their metadata (then "only a minority" is false).

## What was measured first, before this file was written

- `https://pypi.org/integrity/litellm/1.83.14/litellm-1.83.14-py3-none-any.whl/provenance` names publisher `BerriAI/project-releaser`, workflow `publish-litellm.yml`, environment `pypi-publish`.
- `https://pypi.org/integrity/litellm/1.106.2/litellm-1.106.2.tar.gz/provenance` returns 404 ("No provenance available").

These two results changed the claim. The first draft said that a provenance check would have flagged 1.107.0.
