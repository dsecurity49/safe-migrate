#!/bin/sh
# Shared guard for the live-contract entry points in scripts/.
#
# `cargo test --lib <path> -- --exact` exits 0 and prints "0 passed" when the
# name matches nothing, so a renamed or deleted test turned these scripts into
# silent no-ops that still reported success. The guard checks the result
# instead of trusting the exit code.
#
# run_exact_test <script-name> <test-path>
run_exact_test() {
    _name=$1
    _path=$2
    shift 2

    if _output=$(cargo test --locked --lib "$_path" -- --exact --ignored --nocapture "$@" 2>&1); then
        _status=0
    else
        _status=$?
    fi
    printf '%s\n' "$_output"
    [ "$_status" -eq 0 ] || exit "$_status"

    case $_output in
        *"test result: ok. 0 passed"*)
            printf '%s\n' "$_name: no test matched '$_path'." \
                "It was renamed or removed, so this script would have passed" \
                "without running anything." >&2
            exit 1
            ;;
    esac
}
