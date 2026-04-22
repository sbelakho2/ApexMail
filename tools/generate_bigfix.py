#!/usr/bin/env python3
import os
import re
from collections import defaultdict

def scan_repo():
    issues = []
    
    patterns = {
        'Rust': {
            'ext': ['.rs'],
            'rules': [
                (re.compile(r'\.unwrap\(\)'), 'Use of `.unwrap()` - potential panic, handle error properly'),
                (re.compile(r'\.expect\('), 'Use of `.expect()` - potential panic, handle error properly'),
                (re.compile(r'panic!\('), 'Use of `panic!()` - avoid panicking in production code'),
                (re.compile(r'todo!\('), 'Unimplemented `todo!()` macro'),
                (re.compile(r'unimplemented!\('), 'Unimplemented `unimplemented!()` macro'),
                (re.compile(r'unsafe\s*\{'), 'Use of `unsafe` block - verify memory safety'),
                (re.compile(r'TODO|FIXME'), 'TODO or FIXME comment found'),
                (re.compile(r'Mutex<'), 'Use of `Mutex` - consider `RwLock` for read-heavy workloads'),
            ]
        },
        'TypeScript/JavaScript': {
            'ext': ['.ts', '.tsx', '.js', '.jsx'],
            'rules': [
                (re.compile(r'console\.log\('), 'Leftover `console.log` - remove for production'),
                (re.compile(r':\s*any\b'), 'Use of `any` type - reduces type safety'),
                (re.compile(r'@ts-ignore'), 'Use of `@ts-ignore` - fix the underlying type error'),
                (re.compile(r'eslint-disable'), 'Use of `eslint-disable` - fix the linting issue'),
                (re.compile(r'\bvar\s+'), 'Use of `var` - use `let` or `const` instead'),
                (re.compile(r'==\s'), 'Use of `==` - use `===` for strict equality'),
                (re.compile(r'!=\s'), 'Use of `!=` - use `!==` for strict inequality'),
                (re.compile(r'TODO|FIXME'), 'TODO or FIXME comment found'),
            ]
        },
        'Python': {
            'ext': ['.py'],
            'rules': [
                (re.compile(r'print\('), 'Leftover `print` statement - use logging instead'),
                (re.compile(r'except Exception:'), 'Catching broad `Exception` - catch specific exceptions'),
                (re.compile(r'eval\('), 'Use of `eval()` - security risk'),
                (re.compile(r'exec\('), 'Use of `exec()` - security risk'),
                (re.compile(r'TODO|FIXME'), 'TODO or FIXME comment found'),
            ]
        }
    }

    directories_to_scan = ['apps', 'packages', 'services', 'tools']
    
    for root, _, files in os.walk('.'):
        if any(part.startswith('.') for part in root.split(os.sep)):
            continue
        if 'node_modules' in root or 'target' in root or 'dist' in root or 'build' in root or '.venv' in root:
            continue
            
        if not any(root.startswith(f'./{d}') or root == f'./{d}' for d in directories_to_scan):
            continue

        for file in files:
            ext = os.path.splitext(file)[1]
            filepath = os.path.join(root, file)
            
            lang_rules = None
            for lang, config in patterns.items():
                if ext in config['ext']:
                    lang_rules = config['rules']
                    break
            
            if not lang_rules:
                continue
                
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    if len(lines) > 500:
                        issues.append(f"- [ ] **Large File**: `{filepath}` has {len(lines)} lines. Consider refactoring into smaller modules.")
                        
                    for i, line in enumerate(lines):
                        for pattern, message in lang_rules:
                            if pattern.search(line):
                                issues.append(f"- [ ] **{message}** in `{filepath}:{i+1}`\n  ```\n  {line.strip()[:100]}\n  ```")
            except (OSError, UnicodeDecodeError) as exc:
                import logging
                logging.warning('Skipped %s: %s', filepath, exc)

    with open('BigFix.md', 'w', encoding='utf-8') as f:
        f.write("# BigFix: Comprehensive Repository Analysis\n\n")
        f.write(f"Total issues found: {len(issues)}\n\n")
        
        # Group by directory
        grouped_issues = defaultdict(list)
        for issue in issues:
            match = re.search(r'`\./([^:]+):', issue)
            if match:
                path = match.group(1)
                top_dir = path.split('/')[0] if '/' in path else 'root'
                grouped_issues[top_dir].append(issue)
            else:
                grouped_issues['General'].append(issue)
                
        for category, cat_issues in sorted(grouped_issues.items()):
            f.write(f"## {category.capitalize()}\n\n")
            for issue in cat_issues:
                f.write(f"{issue}\n")

    print(f"Generated BigFix.md with {len(issues)} issues.")

if __name__ == '__main__':
    scan_repo()
