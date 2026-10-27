#!/usr/bin/env bash
# Verify that every locked runtime dependency is available as a hash-verified
# binary wheel for Linux ARM64 (aarch64) and CPython 3.12. Downloads only.
set -euo pipefail
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
python3 -m pip download --quiet --disable-pip-version-check --require-hashes --no-deps \
  -r "$(dirname "$0")/../requirements.lock" --only-binary=:all: \
  --platform manylinux2014_aarch64 --platform manylinux_2_17_aarch64 --platform manylinux_2_28_aarch64 \
  --python-version 3.12 --implementation cp --abi cp312 --abi abi3 --abi none -d "$OUT"
echo "aarch64 wheels:"
ls "$OUT" | sed 's/^/  /'
