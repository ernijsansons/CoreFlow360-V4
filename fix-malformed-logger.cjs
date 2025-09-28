const fs = require('fs');
const path = require('path');

// Function to recursively find all TypeScript files
function findTsFiles(dir, files = []) {
  const items = fs.readdirSync(dir);

  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory() && item !== 'node_modules' && item !== '.git') {
      findTsFiles(fullPath, files);
    } else if (item.endsWith('.ts') && !item.endsWith('.d.ts')) {
      files.push(fullPath);
    }
  }

  return files;
}

// Function to fix various malformed logger patterns
function fixMalformedLoggerCalls(content) {
  let fixedContent = content;

  // Fix pattern: { contextField, error: { errorObj } }
  fixedContent = fixedContent.replace(
    /(\w+),\s*error:\s*\{\s*([^}]+)\s*\}/g,
    '$1, error: $2'
  );

  // Fix pattern: { field: value, error: errorVar });
  fixedContent = fixedContent.replace(
    /(\{[^}]*),\s*error:\s*([^}]+)\s*}\)/g,
    '$1, error: $2 })'
  );

  // Fix pattern: logger.info('message' }); (missing opening brace)
  fixedContent = fixedContent.replace(
    /(logger\.(error|warn|info|debug))\([^,]+\s*}\);/g,
    (match, loggerCall, level, message) => {
      const messageMatch = match.match(/\(([^,]+)/);
      if (messageMatch) {
        return `${loggerCall}(${messageMatch[1]});`;
      }
      return match;
    }
  );

  // Fix pattern: logger.info('message', { incomplete context
  fixedContent = fixedContent.replace(
    /(logger\.(error|warn|info|debug))\(([^,]+),\s*\{\s*([^}]*)\s*error:\s*([^}]*)\s*\)/g,
    '$1($3, { $4, error: $5 })'
  );

  // Fix standalone error: patterns
  fixedContent = fixedContent.replace(
    /,\s*error:\s*([^}]+)\s*\)/g,
    ', error: $1 }'
  );

  return fixedContent;
}

// Main execution
console.log('Starting malformed logger fixes...');

const tsFiles = findTsFiles('./src');
let filesFixed = 0;
let totalReplacements = 0;

for (const file of tsFiles) {
  try {
    const content = fs.readFileSync(file, 'utf8');
    const fixedContent = fixMalformedLoggerCalls(content);

    if (content !== fixedContent) {
      fs.writeFileSync(file, fixedContent, 'utf8');
      filesFixed++;
      console.log(`Fixed malformed logger calls in: ${file}`);
    }
  } catch (error) {
    console.error(`Error processing ${file}:`, error.message);
  }
}

console.log(`\nSummary:`);
console.log(`Files processed: ${tsFiles.length}`);
console.log(`Files fixed: ${filesFixed}`);
console.log('\nMalformed logger fixes completed!');