import os
import re

files = [
    "services/mail-server/crates/ui-foundation/src/leptos_views.rs",
    "services/mail-server/crates/ui-foundation/src/primitives.rs",
    "services/mail-server/crates/ui-foundation/src/marketing.rs",
    "services/mail-server/crates/ui-foundation/src/shell.rs"
]

replacements = [
    (r'rounded-md', 'rounded-sm'),
    (r'rounded-lg', 'rounded-sm'),
    (r'rounded-xl', 'rounded-sm'),
    (r'rounded-2xl', 'rounded-sm'),
    (r'rounded-3xl', 'rounded-sm'),
    (r'rounded-\[2rem\]', 'rounded-sm'),
    (r'bg-indigo-600', 'bg-primary'),
    (r'bg-blue-600', 'bg-primary'),
    (r'bg-brand-600', 'bg-primary'),
    (r'bg-indigo-700', 'bg-brand-700'),
    (r'bg-blue-700', 'bg-brand-700'),
    (r'text-indigo-600', 'text-primary'),
    (r'text-blue-600', 'text-primary'),
    (r'text-brand-600', 'text-primary'),
    (r'shadow-sm', ''),
    (r'shadow-md', ''),
    (r'shadow-lg', ''),
    (r'shadow-xl', ''),
    (r'shadow-2xl', ''),
    (r'bg-gray-50', 'bg-surface-50'),
    (r'bg-slate-900', 'bg-surface-950'),
    (r'text-slate-100', 'text-surface-100'),
    (r'text-slate-900', 'text-surface-950'),
    (r'font-semibold', 'font-bold'), # Dieter Rams uses bold for emphasis
]

for file_path in files:
    if not os.path.exists(file_path):
        print(f"Skipping {file_path}")
        continue
    with open(file_path, 'r') as f:
        content = f.read()

    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)

    with open(file_path, 'w') as f:
        f.write(content)
    print(f"Updated {file_path}")
