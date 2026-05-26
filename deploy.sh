#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${CRATES_IO_TOKEN:-}" ]]; then
  echo "Error: CRATES_IO_TOKEN is not set." >&2
  exit 1
fi

cargo publish --token "$CRATES_IO_TOKEN"
