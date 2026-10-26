#!/usr/bin/env bash
# List the v1.106.* and v1.107.* tags in github.com/BerriAI/litellm (public API, no token needed).
set -euo pipefail
date -u +%Y-%m-%dT%H:%M:%SZ
for prefix in v1.106 v1.107; do
  curl -fsS "https://api.github.com/repos/BerriAI/litellm/git/matching-refs/tags/$prefix" \
    | python3 -I -c 'import json,sys; [print(r["ref"], r["object"]["sha"]) for r in json.load(sys.stdin)]'
done
echo "lookalike repo github.com/Berri-AI/litellm: HTTP $(curl -s -o /dev/null -w '%{http_code}' https://api.github.com/repos/Berri-AI/litellm)"
