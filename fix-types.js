const fs = require('fs');
const path = require('path');
const glob = require('glob');

// Common type fixes
const fixes = [
  // Fix unknown type assertions
  {
    pattern: /catch\s*\(\s*error\s*\)/g,
    replacement: 'catch (error: any)'
  },
  {
    pattern: /\.catch\(\s*error\s*=>/g,
    replacement: '.catch((error: any) =>'
  },
  {
    pattern: /\.catch\(\s*\(\s*error\s*\)\s*=>/g,
    replacement: '.catch((error: any) =>'
  },
  // Fix implicit any in map/filter/forEach
  {
    pattern: /\.map\(\s*([a-z_][a-z0-9_]*)\s*=>/gi,
    replacement: '.map(($1: any) =>'
  },
  {
    pattern: /\.filter\(\s*([a-z_][a-z0-9_]*)\s*=>/gi,
    replacement: '.filter(($1: any) =>'
  },
  {
    pattern: /\.forEach\(\s*([a-z_][a-z0-9_]*)\s*=>/gi,
    replacement: '.forEach(($1: any) =>'
  },
  // Fix async function parameters
  {
    pattern: /async\s+\(\s*([a-z_][a-z0-9_]*)\s*\)/gi,
    replacement: 'async ($1: any)'
  }
];

function fixFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;

  for (const fix of fixes) {
    const newContent = content.replace(fix.pattern, fix.replacement);
    if (newContent !== content) {
      modified = true;
      content = newContent;
    }
  }

  if (modified) {
    fs.writeFileSync(filePath, content);
    console.log(`Fixed: ${filePath}`);
    return 1;
  }
  return 0;
}

// Find all TypeScript files
const files = glob.sync('src/**/*.ts', {
  ignore: ['**/node_modules/**', '**/dist/**', '**/*.d.ts']
});

let totalFixed = 0;
for (const file of files) {
  totalFixed += fixFile(file);
}

console.log(`\nTotal files fixed: ${totalFixed}`);