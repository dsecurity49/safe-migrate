#!/bin/bash
# Run all fuzz migration files through the linter, output to file
set -e

DIR="tests/fuzz_migrations/sql"
BIN="./target/debug/safe-migrate"
RESULTS="tests/fuzz_migrations/results"
mkdir -p "$RESULTS"
SUMMARY="$RESULTS/summary.txt"

TOTAL=0; PASS=0; FAIL=0; PARSE_ERR=0; CRASH=0; TIMEOUT=0; HALT=0; CAUTIOUS=0; SAFE_ONLY=0

echo "=== Fuzz Testing: $(ls "$DIR"/*.sql 2>/dev/null | wc -l) SQL files ===" | tee "$SUMMARY"

for f in "$DIR"/*.sql; do
    TOTAL=$((TOTAL+1))
    base=$(basename "$f" .sql)
    
    output=$(timeout 3 "$BIN" lint --no-cache --json --file "$f" 2>&1) 
    exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        TIMEOUT=$((TIMEOUT+1))
        echo "TIMEOUT: $base" >> "$RESULTS/timeouts.txt"
        continue
    fi
    
    if echo "$output" | grep -q "thread.*panicked\|attempt to\|overflow\|assertion failed\|index out of"; then
        CRASH=$((CRASH+1))
        echo "$output" > "$RESULTS/crash_${base}.txt"
        echo "CRASH: $base" | tee -a "$SUMMARY"
        continue
    fi
    
    if echo "$output" | grep -q "^error\["; then
        FAIL=$((FAIL+1))
        echo "$output" > "$RESULTS/error_${base}.txt"
        continue
    fi
    
    if echo "$output" | grep -q "Failed to parse"; then
        PARSE_ERR=$((PARSE+1))
        continue
    fi
    
    verdict=$(echo "$output" | grep -o '"verdict":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ "$verdict" = "HALT" ]; then HALT=$((HALT+1))
    elif [ "$verdict" = "CAUTIOUS" ]; then CAUTIOUS=$((CAUTIOUS+1))
    elif [ "$verdict" = "SAFE" ]; then SAFE_ONLY=$((SAFE_ONLY+1))
    fi
    
    PASS=$((PASS+1))
    
    if [ $((TOTAL % 100)) -eq 0 ]; then
        echo "Progress $TOTAL: P=$PASS F=$FAIL C=$CRASH T=$TIMEOUT H=$HALT CAU=$CAUTIOUS S=$SAFE_ONLY" | tee -a "$SUMMARY"
    fi
done

echo "" | tee -a "$SUMMARY"
echo "=== RESULTS ===" | tee -a "$SUMMARY"
echo "Total:      $TOTAL" | tee -a "$SUMMARY"
echo "Passed:     $PASS" | tee -a "$SUMMARY"
echo "Parse err:  $PARSE_ERR" | tee -a "$SUMMARY"
echo "Crashes:    $CRASH" | tee -a "$SUMMARY"
echo "Errors:     $FAIL" | tee -a "$SUMMARY"
echo "Timeouts:   $TIMEOUT" | tee -a "$SUMMARY"
echo "HALT:       $HALT" | tee -a "$SUMMARY"
echo "CAUTIOUS:   $CAUTIOUS" | tee -a "$SUMMARY"
echo "SAFE:       $SAFE_ONLY" | tee -a "$SUMMARY"

if [ $CRASH -gt 0 ]; then
    echo "" | tee -a "$SUMMARY"
    echo "CRASH FILES:" | tee -a "$SUMMARY"
    for cf in "$RESULTS"/crash_*.txt; do
        echo "--- $(basename "$cf") ---" | tee -a "$SUMMARY"
        head -10 "$cf" | tee -a "$SUMMARY"
    done
fi

if [ $FAIL -gt 0 ]; then
    echo "" | tee -a "$SUMMARY"
    echo "ERROR FILES:" | tee -a "$SUMMARY"
    for ef in "$RESULTS"/error_*.txt; do
        echo "--- $(basename "$ef") ---" | tee -a "$SUMMARY"
        head -5 "$ef" | tee -a "$SUMMARY"
    done
fi
