#!/usr/bin/env bash
# Local CI check for zlicenser-protocol, mirroring .github/workflows/ci.yml.
# Usage: ./test_ci.sh [--fix]
#   --fix   auto-run `cargo fmt` before checking (formats in place)

set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; BLD='\033[1m'; RST='\033[0m'
FAILED=(); SKIPPED=(); FIX=0

for arg in "$@"; do
  case "$arg" in
    --fix) FIX=1 ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

hr()   { printf '%*s\n' 72 '' | tr ' ' '-'; }
step() {
  local label="$1"; shift
  printf "  ${BLD}%-28s${RST}" "$label"
  local out
  if out=$(eval "$@" 2>&1); then echo -e "${GRN}PASS${RST}"
  else echo -e "${RED}FAIL${RST}"; echo "$out" | sed 's/^/    /'; return 1; fi
}
check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo -e "  ${YLW}SKIP${RST}  $1 not installed  →  cargo install $1"; return 1
  fi
}

hr
echo -e "${BLD}zlicenser-protocol CI  $(date '+%Y-%m-%d %H:%M:%S')${RST}"
echo -e "  $REPO"
hr

[[ $FIX -eq 1 ]] && (cd "$REPO" && cargo fmt) && echo -e "  ${GRN}fmt (auto-fixed)${RST}" || true

step "fmt"                    "cd '$REPO' && cargo fmt --check"                                             || FAILED+=(fmt)
step "clippy --all-features"  "cd '$REPO' && cargo clippy -p zlicenser-protocol --all-features -- -D warnings"  || FAILED+=(clippy-all)
step "clippy --no-defaults"   "cd '$REPO' && cargo clippy -p zlicenser-protocol --no-default-features -- -D warnings" || FAILED+=(clippy-none)
step "test"                   "cd '$REPO' && cargo test -p zlicenser-protocol"                              || FAILED+=(test)
step "test --all-features"    "cd '$REPO' && cargo test -p zlicenser-protocol --all-features"               || FAILED+=(test-all)
step "test --no-defaults"     "cd '$REPO' && cargo test -p zlicenser-protocol --no-default-features"        || FAILED+=(test-none)

if check_tool cargo-deny;  then step "deny"  "cd '$REPO' && cargo deny check"  || FAILED+=(deny);  else SKIPPED+=(deny);  fi
if check_tool cargo-audit; then step "audit" "cd '$REPO' && cargo audit"        || FAILED+=(audit); else SKIPPED+=(audit); fi

hr
[[ ${#SKIPPED[@]} -gt 0 ]] && echo -e "${YLW}Skipped:${RST} ${SKIPPED[*]}"
if [[ ${#FAILED[@]} -eq 0 ]]; then
  echo -e "${GRN}${BLD}All checks passed.${RST}"
  exit 0
else
  echo -e "${RED}${BLD}Failed: ${FAILED[*]}${RST}"
  exit 1
fi
