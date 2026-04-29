#!/usr/bin/env python3
"""Debug script to understand the audit false positives."""

import json
import re

from common_paths import data_path

with open(data_path("train_agent.jsonl")) as f:
    for i, line in enumerate(f, 1):
        if i == 22:
            data = json.loads(line)
            text = data.get('text', '')
            
            # Find user's plan
            plan_match = re.search(r'Plan: (\w+)', text)
            print(f"Line 22 User Plan: {plan_match.group(1) if plan_match else 'N/A'}")
            
            # All dedicated IP mentions
            ip_matches = re.findall(r'(\d+)\s*dedicated\s*IPs?\s*included', text, re.IGNORECASE)
            print(f"Dedicated IP mentions found: {ip_matches}")
            
            # This is what the Key features section looks like (extracting it)
            feat_match = re.search(r'## Key features by plan\n(.*?)\n##', text, re.DOTALL)
            if feat_match:
                print("\n--- Key features section: ---")
                print(feat_match.group(1)[:600])
            
            # Check retention mentions
            ret_matches = re.findall(r'(\d+)[-\s]?days?\s*(?:data\s*)?retention', text, re.IGNORECASE)
            print(f"\nRetention mentions: {ret_matches}")
            
            # Check audit log mentions
            audit_matches = re.findall(r'audit\s*logs?', text, re.IGNORECASE)
            print(f"Audit log mentions: {len(audit_matches)}")
            
            break
