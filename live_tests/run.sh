#!/usr/bin/env bash
# Run cached SQL fixtures.
set -uo pipefail
shopt -s nullglob

SCRIPT_DIR="$(CDPATH='' cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCRIPT_DIR}/../target/debug/safe-migrate"

if [ ! -x "$BIN" ]; then
    echo "[!] safe-migrate binary not found; run 'cargo build' first."
    exit 1
fi

CACHE_FILE="${SCRIPT_DIR}/.safe-migrate.cache"

VERBOSE=0
OFFLINE=0
TARGET_DIR=""
TARGET_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --offline)
            OFFLINE=1
            shift
            ;;
        -d|--dir)
            [ "$#" -ge 2 ] || { echo "$1 requires a directory" >&2; exit 1; }
            TARGET_DIR="$2"
            shift 2
            ;;
        -t|--test)
            [ "$#" -ge 2 ] || { echo "$1 requires a SQL file" >&2; exit 1; }
            TARGET_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $(basename "$0") [options]"
            echo "Options:"
            echo "  -v, --verbose    Show individual test results"
            echo "  --offline        Run tests without the cache (--no-cache)"
            echo "  -d, --dir DIR    Run only a specific rule directory (e.g. rule_01_irreversible-migration)"
            echo "  -t, --test FILE  Run only a specific SQL file"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

command -v python3 >/dev/null 2>&1 || {
    echo "[!] python3 is required" >&2
    exit 1
}

if [ "$OFFLINE" -eq 0 ]; then
    [ -f "$CACHE_FILE" ] || {
        echo "[!] frozen cache not found: $CACHE_FILE" >&2
        exit 1
    }
    "$BIN" cache inspect --cache "$CACHE_FILE" --config /dev/null >/dev/null || {
        echo "[!] frozen cache is invalid: $CACHE_FILE" >&2
        exit 1
    }
fi

total_pass=0
total_fail=0
total_skip=0
failures=""

if [ -n "$TARGET_FILE" ]; then
    [ -f "$TARGET_FILE" ] || { echo "Test file not found: $TARGET_FILE" >&2; exit 1; }
    [[ "$TARGET_FILE" == *.sql ]] || { echo "Test file must end in .sql: $TARGET_FILE" >&2; exit 1; }
    dirs=("$(dirname -- "$TARGET_FILE")")
elif [ -n "$TARGET_DIR" ]; then
    target_path="${SCRIPT_DIR}/${TARGET_DIR}"
    [ -d "$target_path" ] || { echo "Rule directory not found: $TARGET_DIR" >&2; exit 1; }
    dirs=("$target_path")
else
    dirs=("${SCRIPT_DIR}"/rule_*/)
fi

[ "${#dirs[@]}" -gt 0 ] || { echo "No rule directories found" >&2; exit 1; }

echo "Starting test runner..."
[ "$OFFLINE" -eq 1 ] && echo "Mode: OFFLINE (--no-cache)"
[ "$OFFLINE" -eq 0 ] && echo "Mode: CACHED (${CACHE_FILE})"

for dir in "${dirs[@]}"; do
    rule_dir=$(basename "$dir")
    
    rule_id="${rule_dir#rule_[0-9][0-9]_}"
    [ -z "$rule_id" ] && rule_id="${rule_dir#rule_[0-9]_}"

    dir_pass=0
    dir_fail=0
    dir_skip=0

    if [ -n "$TARGET_FILE" ]; then
        files=("$TARGET_FILE")
    else
        files=("$dir"/*.sql)
    fi

    # Chain-conflict fixtures run as one ordered migration.
    if [[ "$rule_dir" == *"chain-conflict"* && -z "$TARGET_FILE" ]]; then
        SM_ARGS=("lint-chain" "-d" "$dir")
        if [ "$OFFLINE" -eq 1 ]; then
            SM_ARGS+=("--no-cache")
        else
            SM_ARGS+=("--cache" "$CACHE_FILE")
        fi
        SM_ARGS+=("--json")

        raw_output=$("$BIN" "${SM_ARGS[@]}" 2>&1)
        json=$(echo "$raw_output" | sed -n '/^{/,$ p')

        if [ -z "$json" ]; then
            [ "$VERBOSE" -eq 1 ] && echo "  [!] NO JSON: $rule_dir | Output: $raw_output"
            dir_fail=$((dir_fail + 1))
            failures="$failures  [CRASH] $rule_dir\n"
        else
            violation_rules=$(echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    rules = [v.get('rule_id','') for v in data.get('violations',[])]
    print(','.join(rules))
except:
    print('')
" 2>/dev/null || echo "")

            has_expected=$(echo "$violation_rules" | tr ',' '\n' | grep -x -c "$rule_id" || true)

            if [ "$has_expected" -gt 0 ]; then
                [ "$VERBOSE" -eq 1 ] && echo "  [PASS] $rule_dir"
                dir_pass=$((dir_pass + 1))
            else
                [ "$VERBOSE" -eq 1 ] && echo "  [FAIL] $rule_dir (no '$rule_id', got: $violation_rules)"
                dir_fail=$((dir_fail + 1))
                failures="$failures  [FAIL]  $rule_dir (missed expected $rule_id)\n"
            fi
        fi
    else
        for file in "${files[@]}"; do
            fname=$(basename "$file")

            SM_ARGS=("lint")
            if [ "$OFFLINE" -eq 1 ]; then
                SM_ARGS+=("--no-cache")
            else
                SM_ARGS+=("--cache" "$CACHE_FILE")
            fi
            SM_ARGS+=("--json" "-f" "$file")

            # Reports can follow diagnostics captured from stderr.
            raw_output=$("$BIN" "${SM_ARGS[@]}" 2>&1)
            json=$(echo "$raw_output" | sed -n '/^{/,$ p')
            
            if [ -z "$json" ]; then
                [ "$VERBOSE" -eq 1 ] && echo "  [!] NO JSON: $fname | Output: $raw_output"
                dir_fail=$((dir_fail + 1))
                failures="$failures  [CRASH] $rule_dir/$fname\n"
                continue
            fi

            violation_rules=$(echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    rules = [v.get('rule_id','') for v in data.get('violations',[])]
    print(','.join(rules))
except:
    print('')
" 2>/dev/null || echo "")

            has_expected=$(echo "$violation_rules" | tr ',' '\n' | grep -x -c "$rule_id" || true)

            if [[ "$fname" == safe_* ]]; then
                if [ "$has_expected" -eq 0 ]; then
                    [ "$VERBOSE" -eq 1 ] && echo "  [PASS] $rule_dir/$fname"
                    dir_pass=$((dir_pass + 1))
                else
                    [ "$VERBOSE" -eq 1 ] && echo "  [FAIL] $rule_dir/$fname (expected 0 '$rule_id', got: $violation_rules)"
                    dir_fail=$((dir_fail + 1))
                    failures="$failures  [FAIL]  $rule_dir/$fname (safe but got $rule_id)\n"
                fi
            else
                if [ "$has_expected" -gt 0 ]; then
                    [ "$VERBOSE" -eq 1 ] && echo "  [PASS] $rule_dir/$fname"
                    dir_pass=$((dir_pass + 1))
                else
                    [ "$VERBOSE" -eq 1 ] && echo "  [FAIL] $rule_dir/$fname (no '$rule_id', got: $violation_rules)"
                    dir_fail=$((dir_fail + 1))
                    failures="$failures  [FAIL]  $rule_dir/$fname (missed expected $rule_id)\n"
                fi
            fi
        done
    fi

    total_pass=$((total_pass + dir_pass))
    total_fail=$((total_fail + dir_fail))
    total_skip=$((total_skip + dir_skip))
    
    if [ -z "$TARGET_FILE" ]; then
        if [ "$dir_fail" -gt 0 ] || [ "$dir_skip" -gt 0 ]; then
            echo -e "  ❌ \033[31m$rule_dir:\033[0m $dir_pass pass, $dir_fail fail, $dir_skip skip"
        else
            echo -e "  ✅ \033[32m$rule_dir:\033[0m $dir_pass pass, $dir_fail fail, $dir_skip skip"
        fi
    fi
done

echo ""
echo "=================================================="
total_run=$((total_pass + total_fail))
if [ "$total_run" -eq 0 ]; then
    echo -e " \033[31mNO TESTS RAN\033[0m"
    total_fail=1
elif [ "$total_fail" -eq 0 ] && [ "$total_skip" -eq 0 ]; then
    echo -e " \033[32mALL TESTS PASSED ($total_pass)\033[0m"
else
    echo -e " \033[31mTOTAL: $total_pass passed, $total_fail failed, $total_skip skipped\033[0m"
fi
echo "=================================================="

if [ -n "$failures" ]; then
    echo -e "\nDetailed Failures/Skips:"
    echo -e "$failures"
fi

if [ "$total_fail" -ne 0 ]; then
    exit 1
fi
exit 0
