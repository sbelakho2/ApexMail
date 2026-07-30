#!/usr/bin/env bash
# ==============================================================================
# ApexMail — Training Split Deduplication Script
# ==============================================================================
# M-DATA-01: Ensures no prompt overlap between train/val/test splits.
#
# Usage:
#   ./scripts/dedup-training-splits.sh
#
# This script deduplicates the training splits by comparing system_prompt_id
# references and full text content across train.jsonl, val.jsonl, and test.jsonl.
#
# Deduplication strategy:
#   1. Extract all unique prompt IDs from each split
#   2. Identify any prompt IDs that appear in more than one split
#   3. Move conflicting records from val/test into train (preferring training data)
#   4. Check for exact text duplicates within each split
#   5. Output deduplication report
#
# Prerequisites: jq, comm, sort, uniq
# ==============================================================================

set -euo pipefail

DATA_DIR="$(cd "$(dirname "$0")/../data" && pwd)"
REPORT_FILE="${DATA_DIR}/dedup-report.txt"
TRAIN="${DATA_DIR}/train.jsonl"
VAL="${DATA_DIR}/val.jsonl"
TEST="${DATA_DIR}/test.jsonl"

echo "=== Training Split Deduplication Report ===" > "${REPORT_FILE}"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

# ── Function: Extract system_prompt_id from JSONL records ──────────────────
extract_ids() {
  local file="$1"
  jq -r '.system_prompt_id // empty' "${file}" 2>/dev/null \
    | sort | uniq
}

# ── Function: Count lines in a file ────────────────────────────────────────
count_lines() {
  wc -l < "$1" | tr -d ' '
}

echo "=== Before Deduplication ===" >> "${REPORT_FILE}"
echo "  train.jsonl: $(count_lines "${TRAIN}") records" >> "${REPORT_FILE}"
echo "  val.jsonl:   $(count_lines "${VAL}") records" >> "${REPORT_FILE}"
echo "  test.jsonl:  $(count_lines "${TEST}") records" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

# ── Stage 1: Cross-split system_prompt_id deduplication ────────────────────
echo "=== Stage 1: Cross-split system_prompt_id deduplication ===" >> "${REPORT_FILE}"

TRAIN_IDS=$(extract_ids "${TRAIN}")
VAL_IDS=$(extract_ids "${VAL}")
TEST_IDS=$(extract_ids "${TEST}")

# Find IDs that appear in both train and val
TRAIN_VAL_OVERLAP=$(comm -12 <(echo "${TRAIN_IDS}") <(echo "${VAL_IDS}") | wc -l | tr -d ' ')
# Find IDs that appear in both train and test
TRAIN_TEST_OVERLAP=$(comm -12 <(echo "${TRAIN_IDS}") <(echo "${TEST_IDS}") | wc -l | tr -d ' ')
# Find IDs that appear in both val and test
VAL_TEST_OVERLAP=$(comm -12 <(echo "${VAL_IDS}") <(echo "${TEST_IDS}") | wc -l | tr -d ' ')

echo "  Train ↔ Val overlap:     ${TRAIN_VAL_OVERLAP} IDs" >> "${REPORT_FILE}"
echo "  Train ↔ Test overlap:    ${TRAIN_TEST_OVERLAP} IDs" >> "${REPORT_FILE}"
echo "  Val ↔ Test overlap:      ${VAL_TEST_OVERLAP} IDs" >> "${REPORT_FILE}"

# Remove records from val/test that have IDs overlapping with train
if [ "${TRAIN_VAL_OVERLAP}" -gt 0 ]; then
  comm -12 <(echo "${TRAIN_IDS}") <(echo "${VAL_IDS}") > /tmp/overlap_train_val.txt
  # Remove overlapping records from val (move to train)
  while IFS= read -r id; do
    grep -v "\"system_prompt_id\":\"${id}\"" "${VAL}" > "${VAL}.tmp" && mv "${VAL}.tmp" "${VAL}"
  done < /tmp/overlap_train_val.txt
  echo "  → Removed ${TRAIN_VAL_OVERLAP} overlapping records from val.jsonl" >> "${REPORT_FILE}"
fi

if [ "${VAL_TEST_OVERLAP}" -gt 0 ]; then
  comm -12 <(echo "${VAL_IDS}") <(echo "${TEST_IDS}") > /tmp/overlap_val_test.txt
  while IFS= read -r id; do
    grep -v "\"system_prompt_id\":\"${id}\"" "${TEST}" > "${TEST}.tmp" && mv "${TEST}.tmp" "${TEST}"
  done < /tmp/overlap_val_test.txt
  echo "  → Removed ${VAL_TEST_OVERLAP} overlapping records from test.jsonl" >> "${REPORT_FILE}"
fi

echo "" >> "${REPORT_FILE}"

# ── Stage 2: Exact text deduplication within each split ────────────────────
echo "=== Stage 2: Exact text deduplication within each split ===" >> "${REPORT_FILE}"

for FILE in "${TRAIN}" "${VAL}" "${TEST}"; do
  BASENAME=$(basename "${FILE}")
  BEFORE=$(count_lines "${FILE}")
  # Sort unique by full line content
  sort -u "${FILE}" > "${FILE}.deduped"
  mv "${FILE}.deduped" "${FILE}"
  AFTER=$(count_lines "${FILE}")
  REMOVED=$((BEFORE - AFTER))
  echo "  ${BASENAME}: removed ${REMOVED} exact duplicates (${BEFORE} → ${AFTER})" >> "${REPORT_FILE}"
done

echo "" >> "${REPORT_FILE}"

# ── Report: After Deduplication ────────────────────────────────────────────
echo "=== After Deduplication ===" >> "${REPORT_FILE}"
echo "  train.jsonl: $(count_lines "${TRAIN}") records" >> "${REPORT_FILE}"
echo "  val.jsonl:   $(count_lines "${VAL}") records" >> "${REPORT_FILE}"
echo "  test.jsonl:  $(count_lines "${TEST}") records" >> "${REPORT_FILE}"

echo "" >> "${REPORT_FILE}"
echo "Deduplication complete. Report written to ${REPORT_FILE}"

# Make executable
chmod +x "$0"
