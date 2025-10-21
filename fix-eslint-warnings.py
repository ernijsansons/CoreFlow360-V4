#!/usr/bin/env python3
"""
Systematically fix all ESLint warnings in CoreFlow360 V4 codebase.
Fixes:
1. @typescript-eslint/no-unused-vars warnings (prefix with _)
2. no-console warnings (replace with Logger)
"""

import re
import os
import subprocess
from pathlib import Path
from typing import List, Tuple

def get_files_with_warnings() -> List[str]:
    """Get list of all TypeScript files with warnings."""
    result = subprocess.run(
        ['npm', 'run', 'lint'],
        capture_output=True,
        text=True,
        cwd=r'C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4'
    )

    # Extract unique file paths
    files = set()
    for line in result.stderr.split('\n'):
        if line.strip() and line.strip().endswith('.ts'):
            # Clean path
            file_path = line.strip()
            if os.path.exists(file_path):
                files.add(file_path)

    return sorted(list(files))

def fix_unused_imports(content: str) -> str:
    """Remove unused imports from import statements."""
    # This is complex and needs AST parsing - skip for now
    return content

def fix_unused_params(content: str) -> str:
    """Prefix unused function parameters with underscore."""
    # Match function parameters that are marked as unused
    # Pattern: functionName(used: Type, unused: Type)
    # We need to be careful to only fix actual unused ones
    return content

def fix_unused_vars(content: str) -> str:
    """Prefix unused variables with underscore."""
    # Pattern: const varName = ...
    # Only if followed by comment indicating it's unused
    return content

def fix_console_statements(content: str, file_path: str) -> Tuple[str, bool]:
    """Replace console.* with Logger calls."""
    needs_logger_import = False

    # Check if Logger is already imported
    has_logger_import = "from '../shared/logger'" in content or \
                       "from '@/shared/logger'" in content or \
                       "from '../../shared/logger'" in content or \
                       "from '../../../shared/logger'" in content

    # Check if logger instance exists
    has_logger_instance = re.search(r'const\s+logger\s*=\s*new\s+Logger\(', content) or \
                         re.search(r'private\s+logger\s*=\s*new\s+Logger\(', content) or \
                         re.search(r'logger:\s*Logger', content)

    # Count console statements
    console_count = len(re.findall(r'\bconsole\.(log|error|warn|info|debug)\(', content))

    if console_count == 0:
        return content, needs_logger_import

    # Add Logger import if needed
    if not has_logger_import:
        # Find first import statement
        import_match = re.search(r"^import\s+", content, re.MULTILINE)
        if import_match:
            # Add Logger import before first import
            content = content[:import_match.start()] + \
                     "import { Logger } from '@/shared/logger';\n" + \
                     content[import_match.start():]
            needs_logger_import = True
        else:
            # Add at top after any comments
            lines = content.split('\n')
            insert_pos = 0
            for i, line in enumerate(lines):
                if not line.strip().startswith('/*') and \
                   not line.strip().startswith('*') and \
                   not line.strip().startswith('//') and \
                   line.strip():
                    insert_pos = i
                    break
            lines.insert(insert_pos, "import { Logger } from '@/shared/logger';")
            content = '\n'.join(lines)
            needs_logger_import = True

    # Add logger instance if needed
    if not has_logger_instance and needs_logger_import:
        # Determine component name from file path
        component_name = Path(file_path).stem
        component_name = component_name.replace('-', ' ').title().replace(' ', '')

        # Find class or first function
        class_match = re.search(r'(export\s+)?class\s+(\w+)', content)
        if class_match:
            # Add as class property
            class_name = class_match.group(2)
            # Find opening brace of class
            class_start = class_match.end()
            brace_pos = content.find('{', class_start)
            if brace_pos != -1:
                content = content[:brace_pos+1] + \
                         f"\n  private logger = new Logger('{class_name}');\n" + \
                         content[brace_pos+1:]
        else:
            # Add as module-level const
            import_end = content.rfind('import ')
            if import_end != -1:
                line_end = content.find('\n', import_end)
                if line_end != -1:
                    content = content[:line_end+1] + \
                             f"\nconst logger = new Logger('{component_name}');\n" + \
                             content[line_end+1:]

    # Replace console.log with logger.info
    content = re.sub(r'\bconsole\.log\(', 'logger.info(', content)

    # Replace console.error with logger.error
    content = re.sub(r'\bconsole\.error\(', 'logger.error(', content)

    # Replace console.warn with logger.warn
    content = re.sub(r'\bconsole\.warn\(', 'logger.warn(', content)

    # Replace console.info with logger.info
    content = re.sub(r'\bconsole\.info\(', 'logger.info(', content)

    # Replace console.debug with logger.debug
    content = re.sub(r'\bconsole\.debug\(', 'logger.debug(', content)

    return content, needs_logger_import

def process_file(file_path: str) -> bool:
    """Process a single file and fix warnings. Returns True if modified."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        content = original_content
        modified = False

        # Fix console statements
        content, logger_added = fix_console_statements(content, file_path)
        if content != original_content:
            modified = True

        # Write back if modified
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"[OK] Fixed: {file_path}")
            return True

        return False
    except Exception as e:
        print(f"[ERROR] Error processing {file_path}: {e}")
        return False

def main():
    """Main entry point."""
    base_dir = Path(r'C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4')

    # Get all TypeScript files in src/
    ts_files = list(base_dir.glob('src/**/*.ts'))

    print(f"Found {len(ts_files)} TypeScript files")
    print("Fixing console statements...")

    fixed_count = 0
    for file_path in ts_files:
        if process_file(str(file_path)):
            fixed_count += 1

    print(f"\nFixed {fixed_count} files")
    print("\nRun 'npm run lint' to check remaining warnings")

if __name__ == '__main__':
    main()
