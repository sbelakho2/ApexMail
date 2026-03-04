#!/usr/bin/env python3
"""
Migrate framer-motion components to CSS animations.
Removes 'use client' from components that don't need it (no useState/useEffect).
"""

import re
import os
import glob
import sys

MARKETING_DIR = "apps/marketing/src/components"

# Components that MUST remain client (have useState/useEffect/other hooks)
MUST_REMAIN_CLIENT = {
    "Header.tsx",
    "LiveAPIConsole.tsx",
    "PricingCalculator.tsx",
    "TestimonialsSection.tsx",
    "DeploymentOptions.tsx",
    "LatencyComparison.tsx",
    "RightToBeForgotten.tsx",
    "AuditTrail.tsx",
    "ConsentLedger.tsx",
    "AutoDPA.tsx",
    "StatusOverview.tsx",
    "StatusHero.tsx",
    "StatusHistory.tsx",
    "CodeBlock.tsx",
    "CookieConsentBanner.tsx",
    "BackToTopButton.tsx",
    "InteractiveConsole.tsx",
    "InteractiveCalculator.tsx",
    "PricingFAQ.tsx",
    "PricingPlans.tsx",
    "TimeTravelDemo.tsx",
    "DebugTools.tsx",
    "RenderHistory.tsx",
    "EndpointExplorer.tsx",
    "CompetitorBreakdown.tsx",
    "DemoErrorBoundary.tsx",
}

def needs_client(filepath, content):
    """Check if file uses useState, useEffect, or other client-only hooks"""
    basename = os.path.basename(filepath)
    if basename in MUST_REMAIN_CLIENT:
        return True
    # Check for hooks that require client
    client_patterns = [
        r'\buseState\b',
        r'\buseEffect\b',
        r'\buseCallback\b',
        r'\buseReducer\b',
        r'\bwindow\b',
        r'\bdocument\b',
        r'\bonClick\b',
        r'\bonChange\b',
        r'\bonSubmit\b',
        r'\bonKeyDown\b',
    ]
    for pat in client_patterns:
        if re.search(pat, content):
            return True
    return False

def transform_file(filepath):
    """Transform a single file to remove framer-motion"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    basename = os.path.basename(filepath)
    
    # Skip if no framer-motion
    if 'framer-motion' not in content:
        # But check if we can remove 'use client' for files with useInView only
        if "'use client'" in content and not needs_client(filepath, content):
            # Check if useInView is the only reason for 'use client'
            if 'useInView' in content and 'motion' not in content:
                content = remove_use_client(content)
                content = remove_useinview(content)
        if content != original:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  [useInView only] {filepath}")
            return True
        return False

    print(f"  Transforming {filepath}...")
    
    # 1. Remove framer-motion import
    content = re.sub(r"import\s*\{[^}]*\}\s*from\s*['\"]framer-motion['\"];\s*\n", '', content)
    
    # 2. Remove useInView import (if present)
    content = re.sub(r"import\s*\{\s*useInView\s*\}\s*from\s*['\"]react-intersection-observer['\"];\s*\n", '', content)
    
    # 3. Remove useInView hook call
    content = re.sub(r"\s*const\s*\[ref,\s*inView\]\s*=\s*useInView\(\{[^}]*\}\);\s*\n", '\n', content)
    
    # 4. Remove ref={ref} from section elements
    content = re.sub(r'\s+ref=\{ref\}', '', content)
    
    # 5. Replace motion.div/motion.section with regular elements + CSS classes
    # Pattern: <motion.div initial={...} animate={...} transition={...} className="...">
    # We need to handle multi-line motion elements
    
    # Replace <motion.div ...> with <div className="animate-in ...">
    content = replace_motion_elements(content)
    
    # 6. Replace </motion.div> with </div>
    content = content.replace('</motion.div>', '</div>')
    content = content.replace('</motion.section>', '</section>')
    content = content.replace('</motion.span>', '</span>')
    content = content.replace('</motion.p>', '</p>')
    
    # 7. Remove AnimatePresence wrapper
    content = re.sub(r'<AnimatePresence[^>]*>\s*\n?', '', content)
    content = content.replace('</AnimatePresence>', '')
    
    # 8. Remove 'use client' if not needed
    if not needs_client(filepath, content):
        content = remove_use_client(content)
    
    # 9. Clean up empty lines
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  ✓ Migrated: {basename}")
        return True
    return False

def remove_use_client(content):
    """Remove 'use client' directive"""
    content = re.sub(r"'use client';\s*\n\n?", '', content)
    content = re.sub(r'"use client";\s*\n\n?', '', content)
    return content

def remove_useinview(content):
    """Remove useInView-related code"""
    content = re.sub(r"import\s*\{\s*useInView\s*\}\s*from\s*['\"]react-intersection-observer['\"];\s*\n", '', content)
    content = re.sub(r"\s*const\s*\[ref,\s*inView\]\s*=\s*useInView\(\{[^}]*\}\);\s*\n", '\n', content)
    content = re.sub(r'\s+ref=\{ref\}', '', content)
    return content

def replace_motion_elements(content):
    """Replace <motion.X ...> with <X className="animate-in ...">"""
    
    # First handle motion elements with transition delay for staggered animations
    # Pattern: <motion.div ... transition={{ delay: X }} className="...">
    
    # Handle self-closing motion elements
    content = re.sub(
        r'<motion\.(\w+)([^>]*?)\s*/\s*>',
        lambda m: replace_single_motion(m.group(1), m.group(2), self_closing=True),
        content,
        flags=re.DOTALL
    )
    
    # Handle opening motion elements
    content = re.sub(
        r'<motion\.(\w+)([^>]*?)>',
        lambda m: replace_single_motion(m.group(1), m.group(2), self_closing=False),
        content,
        flags=re.DOTALL
    )
    
    return content

def replace_single_motion(tag, attrs, self_closing=False):
    """Replace a single motion element"""
    
    # Extract className if present
    class_match = re.search(r'className="([^"]*)"', attrs)
    class_match_expr = re.search(r'className=\{([^}]*)\}', attrs)
    
    existing_classes = ''
    if class_match:
        existing_classes = class_match.group(1)
    
    # Extract delay from transition prop
    delay_match = re.search(r'transition=\{\{[^}]*delay:\s*([\d.]+(?:\s*\+\s*\w+\s*\*\s*[\d.]+)?)', attrs)
    delay_class = ''
    if delay_match:
        delay_val = delay_match.group(1).strip()
        # Handle simple numeric delays
        try:
            delay_num = float(delay_val)
            if delay_num <= 0.1:
                delay_class = 'delay-100'
            elif delay_num <= 0.2:
                delay_class = 'delay-200'
            elif delay_num <= 0.3:
                delay_class = 'delay-300'
            elif delay_num <= 0.4:
                delay_class = 'delay-400'
            elif delay_num <= 0.5:
                delay_class = 'delay-500'
            elif delay_num <= 0.6:
                delay_class = 'delay-500' # cap at 500ms
            else:
                delay_class = 'delay-500'
        except ValueError:
            pass  # Complex expression like index * 0.1
    
    # Build new class list
    new_classes = 'animate-in'
    if delay_class:
        new_classes += f' {delay_class}'
    if existing_classes:
        new_classes += f' {existing_classes}'
    
    # Remove motion-specific props (initial, animate, transition, exit, key with activeIndex, whileInView, viewport)
    cleaned_attrs = attrs
    # Remove initial={...}
    cleaned_attrs = re.sub(r'\s*initial=\{\{[^}]*\}\}', '', cleaned_attrs)
    # Remove animate={...} (possibly with ternary)
    cleaned_attrs = re.sub(r'\s*animate=\{[^}]*\{[^}]*\}[^}]*\}', '', cleaned_attrs)
    cleaned_attrs = re.sub(r'\s*animate=\{\{[^}]*\}\}', '', cleaned_attrs)
    # Remove transition={...}
    cleaned_attrs = re.sub(r'\s*transition=\{\{[^}]*\}\}', '', cleaned_attrs)
    # Remove exit={...}
    cleaned_attrs = re.sub(r'\s*exit=\{\{[^}]*\}\}', '', cleaned_attrs)
    # Remove whileInView, viewport, whileHover, whileTap
    cleaned_attrs = re.sub(r'\s*whileInView=\{\{[^}]*\}\}', '', cleaned_attrs)
    cleaned_attrs = re.sub(r'\s*viewport=\{\{[^}]*\}\}', '', cleaned_attrs)
    cleaned_attrs = re.sub(r'\s*whileHover=\{\{[^}]*\}\}', '', cleaned_attrs)
    cleaned_attrs = re.sub(r'\s*whileTap=\{\{[^}]*\}\}', '', cleaned_attrs)
    # Remove variants={...}
    cleaned_attrs = re.sub(r'\s*variants=\{[^}]*\}', '', cleaned_attrs)
    
    # Replace or add className
    if class_match:
        cleaned_attrs = cleaned_attrs.replace(f'className="{existing_classes}"', f'className="{new_classes}"')
    elif class_match_expr:
        # Keep expression-based className, prepend animate-in
        pass  # Leave as-is for complex cases
    else:
        cleaned_attrs += f' className="{new_classes}"'
    
    # Clean up extra whitespace
    cleaned_attrs = re.sub(r'\s+', ' ', cleaned_attrs).strip()
    if cleaned_attrs:
        cleaned_attrs = ' ' + cleaned_attrs
    
    closing = ' />' if self_closing else '>'
    return f'<{tag}{cleaned_attrs}{closing}'

def main():
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Find all tsx files in marketing components
    files = glob.glob(f'{MARKETING_DIR}/**/*.tsx', recursive=True)
    
    migrated = 0
    skipped = 0
    
    print(f"\n{'='*60}")
    print("  FRAMER-MOTION MIGRATION")
    print(f"{'='*60}")
    print(f"  Found {len(files)} component files\n")
    
    for filepath in sorted(files):
        if transform_file(filepath):
            migrated += 1
        else:
            skipped += 1
    
    print(f"\n{'='*60}")
    print(f"  DONE: {migrated} migrated, {skipped} skipped")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
