#!/usr/bin/env bash
set -euo pipefail

echo "=================================================================="
echo "LOTL-FORGE ZERO-LEAK & SECURITY HYGIENE GATE"
echo "=================================================================="

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    mapfile -t TRACKED_FILES < <(git ls-files)
else
    mapfile -t TRACKED_FILES < <(find . -type f -not -path './.git/*' -not -path './__pycache__/*')
fi

if [ "${#TRACKED_FILES[@]}" -eq 0 ]; then
    mapfile -t TRACKED_FILES < <(find . -type f -not -path './.git/*' -not -path './__pycache__/*')
fi

HOME_PATTERN="/""home""/"
USERS_PATTERN="/""Users""/"
WIN_USERS_PATTERN="C:\\\\""Users\\\\"
SECRET_PATTERN="(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"

LEAK_FOUND=0

echo "[1/4] Auditing tracked files for absolute home directory paths..."
for f in "${TRACKED_FILES[@]}"; do
    [ -f "$f" ] || continue
    if grep -nE "${HOME_PATTERN}|${USERS_PATTERN}|${WIN_USERS_PATTERN}" "$f" >/dev/null 2>&1; then
        echo "  [FAIL] Absolute user path detected in: $f"
        LEAK_FOUND=1
    fi
done

echo "[2/4] Auditing tracked files for current OS username (${USER:-unknown})..."
if [ -n "${USER:-}" ]; then
    for f in "${TRACKED_FILES[@]}"; do
        [ -f "$f" ] || continue
        if grep -niw "${USER}" "$f" >/dev/null 2>&1; then
            echo "  [FAIL] OS username '${USER}' detected in: $f"
            LEAK_FOUND=1
        fi
    done
fi

echo "[3/4] Auditing tracked files for hardcoded credential or API token patterns..."
for f in "${TRACKED_FILES[@]}"; do
    [ -f "$f" ] || continue
    if grep -nE "${SECRET_PATTERN}" "$f" >/dev/null 2>&1; then
        echo "  [FAIL] Credential token pattern detected in: $f"
        LEAK_FOUND=1
    fi
done

if [ "${LEAK_FOUND}" -ne 0 ]; then
    echo "[ERROR] Security hygiene gate failed."
    exit 1
fi
echo "  [PASS] Zero path, username, or token leaks found across ${#TRACKED_FILES[@]} files."

echo "[4/4] Running unit test suite..."
python3 -m unittest discover -s tests -v

echo "=================================================================="
echo "[PASS] ALL SECURITY HYGIENE CHECKS AND UNIT TESTS SUCCEEDED"
echo "=================================================================="
