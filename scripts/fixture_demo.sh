#!/usr/bin/env bash
# Run ioc_check.py on the harmless fixtures from tests/fixtures.py: an infected
# and a clean venv, a `docker save` tarball and an OCI archive.
set -uo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
python3 -I "$repo/tests/fixtures.py" fx >/dev/null
for args in "env fx/infected-venv" "env fx/clean-venv" "scan fx/image-docker-save.tar" "scan fx/image-oci.tar" "scan fx/image-oci-clean.tar"; do
  echo "\$ python3 -I -S ioc_check.py $args"
  # shellcheck disable=SC2086
  python3 -I -S "$repo/ioc_check.py" $args > out.txt
  code=$?
  sed "s#$work/##g" out.txt
  echo "(exit $code)"
  echo
done
