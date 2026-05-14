#!/usr/bin/env python3
"""Centralized path constants for the AI training pipeline.

All scripts in ``apps/ai/training/`` should import from this module rather
than hardcoding paths relative to ``__file__`` or absolute paths such as
``/workspace/…``.

Override the default data directory by setting the ``DATA_DIR`` environment
variable — this is useful when running on cloud instances (Vast.ai, RunPod,
etc.) where the project layout may differ from the local repo.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Project root ────────────────────────────────────────────────────────
# This file lives at:  apps/ai/training/common_paths.py
# Project root is 4 directories up.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
PROJECT_ROOT: Path = _PROJECT_ROOT

# ── Data directory (overridable via env) ────────────────────────────────
DATA_DIR: Path = Path(os.environ.get("DATA_DIR", _PROJECT_ROOT / "data"))

# ── Common data-file paths ──────────────────────────────────────────────
TRAIN_JSONL: Path              = DATA_DIR / "train_agent.jsonl"
VAL_JSONL: Path                = DATA_DIR / "val.jsonl"
TEST_JSONL: Path               = DATA_DIR / "test.jsonl"
GOLDEN_QA_JSONL: Path          = DATA_DIR / "golden_qa.jsonl"
RECOVERED_TRAINING_JSONL: Path = DATA_DIR / "recovered_training.jsonl"
SYSTEM_PROMPTS_JSON: Path      = DATA_DIR / "system_prompts.json"
MANIFEST_JSON: Path            = DATA_DIR / "manifest.json"
