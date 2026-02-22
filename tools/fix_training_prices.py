#!/usr/bin/env python3
"""Fix pricing inconsistencies in train_agent.jsonl"""
import re

# Read the file
with open('data/train_agent.jsonl', 'r') as f:
    content = f.read()

# Fix table rows in assistant responses
content = re.sub(r'\| \*\*Starter\*\* \| \$29 \| 25,000', '| **Starter** | $25 | 50,000', content)
content = re.sub(r'\| \*\*Free\*\* \| \$0 \| 1,000', '| **Free** | $0 | 3,000', content)
content = re.sub(r'\| \*\*Pro\*\* \| \$65 \| 50,000', '| **Pro** | $65 | 150,000', content)
content = re.sub(r'\| \*\*Growth\*\* \| \$150 \| 100,000', '| **Growth** | $150 | 500,000', content)
content = re.sub(r'\| \*\*Scale\*\* \| \$350 \| 500,000', '| **Scale** | $350 | 2,000,000', content)
content = re.sub(r'\| \*\*Enterprise\*\* \| \$800 \| 2,000,000', '| **Enterprise** | $800 | 5,000,000', content)

# Fix bare plan references  
content = re.sub(r'Starter \(\$29\)', 'Starter ($25)', content)
content = re.sub(r'Starter plan \(\$29\)', 'Starter plan ($25)', content)

# Fix "Starter ($25) | $29" style (contradictory)
content = re.sub(r'Starter \(\$25\) \| \$29', 'Starter ($25) | $25', content)

# Fix 25,000 emails for Starter
content = re.sub(r'Includes 25,000 emails', 'Includes 50,000 emails', content)
content = re.sub(r'includes 25,000 emails', 'includes 50,000 emails', content)
content = re.sub(r'you get 25,000 emails included', 'you get 50,000 emails included', content)
content = re.sub(r'get 25,000 emails', 'get 50,000 emails', content)

# Fix Free 1,000 emails 
content = re.sub(r'Free \| \$0 \| 1,000', 'Free | $0 | 3,000', content)

with open('data/train_agent.jsonl', 'w') as f:
    f.write(content)

print("Fixed training data pricing")
