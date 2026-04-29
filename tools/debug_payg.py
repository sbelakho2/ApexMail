#!/usr/bin/env python3
"""Debug script to check flagged PAYG examples."""

import json
import re

from common_paths import data_path

PAYG_LINES = [3, 115, 160, 189, 263, 264, 287, 398, 416, 505, 763, 779, 823, 906, 1001]

with open(data_path("train_agent.jsonl")) as f:
    for i, line in enumerate(f, 1):
        if i in PAYG_LINES:
            data = json.loads(line)
            text = data.get('text', '')
            
            # Extract assistant responses
            assistant_parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
            assistant_text = '\n'.join(assistant_parts)
            
            if 'PAYG' in assistant_text or 'Pay-As-You-Go' in assistant_text:
                print(f"\n{'='*70}")
                print(f"LINE {i}")
                print("="*70)
                # Show just the relevant part of the assistant response
                for part in assistant_parts:
                    if 'PAYG' in part or 'Pay-As-You-Go' in part:
                        # Show first 500 chars of this response
                        print(part[:800])
                        print("...")
