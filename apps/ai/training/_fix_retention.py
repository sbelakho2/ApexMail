#!/usr/bin/env python3
"""Fix remaining fabricated retention tables in train_agent.jsonl."""

with open("data/train_agent.jsonl") as f:
    content = f.read()

# Fix 1: The broken "Body Retention | Event Retention" table (2 occurrences)
# Replace the entire fabricated answer section
old_body_table = (
    "Message body retention varies by plan:\\n\\n"
    "| Plan | Body Retention | Event Retention |\\n"
    "|---|---|---|\\n"
    "| Starter | **30 days** |\\n"
    "| Growth | **90 days** |\\n"
    "| Scale | **365 days** |\\n"
    "| Enterprise | **730 days** |\\n\\n"
    "After the retention window, the email body is purged. Metadata and delivery events are"
)
new_body_table = (
    "Data retention varies by plan:\\n\\n"
    "| Plan | Retention |\\n"
    "|------|----------|\\n"
    "| Free | 7 days |\\n"
    "| Starter | 30 days |\\n"
    "| Pro | 60 days |\\n"
    "| Growth | 90 days |\\n"
    "| Scale | 365 days |\\n"
    "| Enterprise | 730 days |\\n\\n"
    "After the retention window, the data is purged. Metadata and delivery events are"
)

c1 = content.count(old_body_table)
print(f"Fix 1 - broken body/event table: {c1} occurrences")
content = content.replace(old_body_table, new_body_table)

# Fix 2: The redundant "**Message body retention** (shorter):" section (1 occurrence)
# This now has the same values as the main table above it, so it's redundant
# Replace the whole redundant section
old_redundant = (
    "\\n\\n**Message body retention** (shorter):\\n"
    "| Plan | Retention |\\n"
    "|------|----------|\\n"
    "| Starter | 30 days |\\n"
    "| Growth | 90 days |\\n"
    "| Scale | 365 days |\\n"
    "| Enterprise | 730 days |\\n\\n"
)
new_redundant = "\\n\\n"

c2 = content.count(old_redundant)
print(f"Fix 2 - redundant body retention section: {c2} occurrences")
content = content.replace(old_redundant, new_redundant)

with open("data/train_agent.jsonl", "w") as f:
    f.write(content)

# Verify
with open("data/train_agent.jsonl") as f:
    content = f.read()

remaining_body = content.count("body retention") + content.count("Body Retention")
remaining_event = content.count("Event Retention")
remaining_message = content.count("Message body")
print(f"\nRemaining 'body retention' / 'Body Retention': {remaining_body}")
print(f"Remaining 'Event Retention': {remaining_event}")
print(f"Remaining 'Message body': {remaining_message}")
print("Done!")
