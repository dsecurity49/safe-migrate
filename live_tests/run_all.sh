#!/bin/bash
# Run all live test files through safe-migrate lint
# Checks violations against the expected rule_id derived from the directory name.
set -uo pipefail

BIN="$(dirname "$0")/../target/debug/safe-migrate"
total_pass=0
total_fail=0
total_skip=0
failures=""

for dir in "$(dirname "$0")"/rule_*/; do
    rule_dir=$(basename "$dir")
    # Extract rule_id from dir name: rule_NN_rule-id  →  rule-id
    # Handles hyphenated IDs like "blocking-partition-mutation"
    rule_id="${rule_dir#rule_[0-9][0-9]_}"
    [ -z "$rule_id" ] && rule_id="${rule_dir#rule_[0-9]_}"

    dir_pass=0
    dir_fail=0
    dir_skip=0

    for file in "$dir"/*.sql; do
        [ -f "$file" ] || continue
        fname=$(basename "$file")

        # Run safe-migrate lint, extract JSON (skip the "Analyzing migration:" line)
        json=$( "$BIN" lint -f "$file" --json 2>/dev/null | sed -n '/^{/,$ p' )
        if [ -z "$json" ]; then
            echo "  [!] NO JSON: $fname"
            dir_fail=$((dir_fail + 1))
            continue
        fi

        # Extract the rule_ids from all violations
        violation_rules=$(echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = [v.get('rule_id','') for v in data.get('violations',[])]
print(','.join(rules))
" 2>/dev/null || echo "")

        has_expected=$(echo "$violation_rules" | tr ',' '\n' | grep -x -c "$rule_id" || true)

        if [[ "$fname" == safe_* ]]; then
            if [ "$has_expected" -eq 0 ]; then
                echo "  [PASS] $rule_dir/$fname"
                dir_pass=$((dir_pass + 1))
            else
                echo "  [FAIL] $rule_dir/$fname (expected 0 '$rule_id' violations, got: $violation_rules)"
                dir_fail=$((dir_fail + 1))
                failures="$failures  $rule_dir/$fname (safe but got $rule_id)\n"
            fi
        else
            if [ "$has_expected" -gt 0 ]; then
                echo "  [PASS] $rule_dir/$fname"
                dir_pass=$((dir_pass + 1))
            else
                echo "  [SKIP] $rule_dir/$fname (no '$rule_id' violation - rules: $violation_rules)"
                dir_skip=$((dir_skip + 1))
            fi
        fi
    done

    total_pass=$((total_pass + dir_pass))
    total_fail=$((total_fail + dir_fail))
    total_skip=$((total_skip + dir_skip))
    echo "  -> $rule_dir: $dir_pass pass, $dir_fail fail, $dir_skip skip"
    echo ""
done

echo "=============================="
echo "TOTAL: $total_pass passed, $total_fail failed, $total_skip skipped"
echo "=============================="
if [ -n "$failures" ]; then
    echo "FAILURES:"
    echo -e "$failures"
fi
exit $total_fail
