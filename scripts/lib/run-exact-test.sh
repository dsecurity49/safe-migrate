#!/bin/sh
# Shared guard for the live-contract entry points in scripts/.
#
# `cargo test --lib <path> -- --exact` exits 0 and prints "0 passed" when the
# name matches nothing, so a renamed or deleted test turned these scripts into
# silent no-ops that still reported success. The guard checks the result
# instead of trusting the exit code.
#
# Output is teed rather than captured, so a long differential run still shows
# progress. Cargo's status is carried through a side file because a pipeline
# would otherwise report tee's status instead.
#
# run_exact_test <script-name> <test-path>
run_exact_test() {
    _name=$1
    _path=$2
    shift 2

    _log=$(mktemp) || exit 1
    _status_file=$(mktemp) || exit 1
    # shellcheck disable=SC2064
    trap "rm -f '$_log' '$_status_file'" EXIT INT TERM

    # `|| _status=$?` keeps a failing cargo from tripping the caller's errexit
    # before the status reaches the file.
    _status=0
    { cargo test --locked --lib "$_path" -- --exact --ignored --nocapture "$@" 2>&1 || _status=$?
        printf '%s' "$_status" > "$_status_file"
    } | tee "$_log"

    _status=$(cat "$_status_file" 2>/dev/null || printf '%s' 1)
    case $_status in
        '' | *[!0-9]*) _status=1 ;;
    esac
    [ "$_status" -eq 0 ] || exit "$_status"

    if grep -q "test result: ok\. 0 passed" "$_log"; then
        printf '%s\n' "$_name: no test matched '$_path'." \
            "It was renamed or removed, so this script would have passed" \
            "without running anything." >&2
        exit 1
    fi
}
