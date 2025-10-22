#!/usr/bin/env node
/**
 * Script to automatically fix console warnings by replacing with Logger
 */

const fs = require('fs');
const path = require('path');

function fixConsoleInFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');

    // Check if file already has Logger import
    const hasLoggerImport = content.includes("from '../shared/logger'") ||
                           content.includes("from './shared/logger'") ||
                           content.includes("from '@/shared/logger'");

    let newContent = content;

    // Add Logger import if not present and file has console statements
    if (!hasLoggerImport && /console\.(log|error|warn|debug|info)/.test(content)) {
      // Find the last import statement
      const importMatch = content.match(/^import .* from .*;$/gm);
      if (importMatch && importMatch.length > 0) {
        const lastImport = importMatch[importMatch.length - 1];
        const lastImportIndex = content.lastIndexOf(lastImport);
        const insertPosition = lastImportIndex + lastImport.length;

        newContent = content.slice(0, insertPosition) +
                    "\nimport { Logger } from '../shared/logger';" +
                    content.slice(insertPosition);
      }

      // Add logger instance after imports
      const classMatch = newContent.match(/^export (class|function)/m);
      if (classMatch) {
        const insertPosition = newContent.indexOf(classMatch[0]);
        newContent = newContent.slice(0, insertPosition) +
                    "\nconst logger = new Logger({ component: '" + path.basename(filePath, '.ts') + "' });\n\n" +
                    newContent.slice(insertPosition);
      }
    }

    // Replace console statements
    newContent = newContent
      .replace(/console\.log\(/g, 'logger.info(')
      .replace(/console\.error\(/g, 'logger.error(')
      .replace(/console\.warn\(/g, 'logger.warn(')
      .replace(/console\.debug\(/g, 'logger.debug(')
      .replace(/console\.info\(/g, 'logger.info(');

    // Only write if something changed
    if (newContent !== content) {
      fs.writeFileSync(filePath, newContent, 'utf8');
      console.log(`✓ Fixed ${filePath}`);
      return true;
    }

    return false;
  } catch (error) {
    console.error(`✗ Error fixing ${filePath}:`, error.message);
    return false;
  }
}

// Get files from command line or use default list
const files = process.argv.slice(2);

if (files.length === 0) {
  console.log('Usage: node fix-console-warnings.js <file1> <file2> ...');
  process.exit(1);
}

let fixed = 0;
for (const file of files) {
  if (fixConsoleInFile(file)) {
    fixed++;
  }
}

console.log(`\nFixed ${fixed}/${files.length} files`);
