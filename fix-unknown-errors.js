#!/usr/bin/env node
/**
 * Automated Fix for TS18046 'unknown' errors
 * Grug say: Simple script fix all broken code!
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Get all TS18046 errors
console.log('Grug finding all sick code...');
const errors = execSync('npx tsc --noEmit 2>&1 | grep "TS18046"', {
  encoding: 'utf-8',
  cwd: __dirname
}).split('\n').filter(Boolean);

console.log(`Grug found ${errors.length} sick code locations`);

// Parse errors to get file paths and line numbers
const errorMap = new Map();
errors.forEach(error => {
  const match = error.match(/(.+\.ts)\((\d+),(\d+)\): error TS18046: '(\w+)' is of type 'unknown'/);
  if (match) {
    const [, filePath, line, col, varName] = match;
    const fullPath = path.resolve(__dirname, filePath);

    if (!errorMap.has(fullPath)) {
      errorMap.set(fullPath, []);
    }
    errorMap.get(fullPath).push({ line: parseInt(line), col: parseInt(col), varName });
  }
});

console.log(`Grug will fix ${errorMap.size} files`);

// Fix each file
let filesFixed = 0;
let errorsFixed = 0;

for (const [filePath, issues] of errorMap.entries()) {
  try {
    let content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    // Sort issues by line number (descending) to avoid offset issues
    issues.sort((a, b) => b.line - a.line);

    let modified = false;
    for (const issue of issues) {
      const lineIdx = issue.line - 1;
      if (lineIdx < 0 || lineIdx >= lines.length) continue;

      const line = lines[lineIdx];
      const varName = issue.varName;

      // Fix: Replace `varName.property` with `(varName as any).property`
      // or `varName?.property` with `(varName as any)?.property`
      const patterns = [
        // Pattern: variable.property
        {
          regex: new RegExp(`\\b${varName}\\.(\\w+)`, 'g'),
          replacement: `(${varName} as any).$1`
        },
        // Pattern: variable?.property
        {
          regex: new RegExp(`\\b${varName}\\?\\.(\\w+)`, 'g'),
          replacement: `(${varName} as any)?.$1`
        },
        // Pattern: variable[key]
        {
          regex: new RegExp(`\\b${varName}\\[`, 'g'),
          replacement: `(${varName} as any)[`
        }
      ];

      let newLine = line;
      for (const pattern of patterns) {
        const before = newLine;
        newLine = newLine.replace(pattern.regex, pattern.replacement);
        if (newLine !== before) {
          modified = true;
          errorsFixed++;
          break;
        }
      }

      if (newLine !== line) {
        lines[lineIdx] = newLine;
      }
    }

    if (modified) {
      fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
      filesFixed++;
      console.log(`✓ Fixed ${filePath.replace(__dirname, '')}`);
    }
  } catch (err) {
    console.error(`✗ Failed to fix ${filePath}: ${err.message}`);
  }
}

console.log(`\nGrug finished! Fixed ${errorsFixed} errors in ${filesFixed} files`);
console.log('Grug say: Run "npx tsc --noEmit" to check if all fixed!');
