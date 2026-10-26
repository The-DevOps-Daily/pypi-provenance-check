#!/usr/bin/env bash
# Cryptographically verify a litellm wheel's PyPI attestation with the
# pypi-attestations CLI, twice: once against the repository litellm's metadata
# names, once against the repository that actually published it.
#
#   bash scripts/verify_with_pypi_attestations.sh   (needs uv; downloads a 16 MB wheel)
#
# litellm 1.83.14 is the last litellm release with an attestation (26 April 2026).
set -uo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export UV_CACHE_DIR="$work/uv-cache"
tool=(uvx --quiet --from "pypi-attestations==0.0.30" pypi-attestations)
file="pypi:litellm-1.83.14-py3-none-any.whl"

for repo in https://github.com/BerriAI/litellm https://github.com/BerriAI/project-releaser; do
  echo "\$ pypi-attestations verify pypi --repository $repo $file"
  "${tool[@]}" verify pypi --repository "$repo" "$file" 2>&1
  echo "(exit $?)"
  echo
done
