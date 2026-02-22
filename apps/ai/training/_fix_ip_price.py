#!/usr/bin/env python3
"""Fix dedicated IP price $50 → $49 in train_agent.jsonl."""

with open("/Users/sabelakhoua/IdeaProjects/ApexMail/data/train_agent.jsonl", "r") as f:
    content = f.read()

print("Before:")
print(f"  '$50.00' count: {content.count('$50.00')}")
print(f"  '$449.00' count: {content.count('$449.00')}")
print(f"  'extra $50' count: {content.count('extra $50')}")

# Fix dedicated IP pricing
content = content.replace(
    "Additional dedicated IP | $50.00",
    "Additional dedicated IP | $49.00"
)
content = content.replace(
    "**Total** | **$449.00**",
    "**Total** | **$448.00**"
)
content = content.replace(
    "The extra $50 is for an **additional dedicated IP",
    "The extra $49 is for an **additional dedicated IP"
)

print("\nAfter:")
print(f"  '$50.00' count: {content.count('$50.00')}")
print(f"  '$449.00' count: {content.count('$449.00')}")
print(f"  'extra $50' count: {content.count('extra $50')}")
print(f"  '$49.00' (dedicated IP): {content.count('dedicated IP | $49.00')}")
print(f"  '$448.00' (total): {content.count('$448.00')}")

with open("/Users/sabelakhoua/IdeaProjects/ApexMail/data/train_agent.jsonl", "w") as f:
    f.write(content)

print("\nDone!")
