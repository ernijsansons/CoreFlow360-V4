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

// Function to fix logger calls in a file
function fixLoggerCalls(content) {
  // Pattern: logger.method('message', errorVar, { context })
  // Should become: logger.method('message', { context, error: errorVar })

  // Match logger calls with 3 arguments
  const pattern = /(this\.logger\.(error|warn|info|debug))\(\s*([^,]+),\s*([^,]+),\s*(\{[^}]*\})\s*\)/g;

  return content.replace(pattern, (match, loggerCall, level, message, errorVar, context) => {
    // Extract the variable name from errorVar (remove any casting or string conversion)
    const cleanErrorVar = errorVar.trim();

    // Remove the closing brace from context and add error field
    const contextWithoutBrace = context.slice(0, -1).trim();
    const newContext = contextWithoutBrace === '{' ?
      `{ error: ${cleanErrorVar} }` :
      `${contextWithoutBrace}, error: ${cleanErrorVar} }`;

    return `${loggerCall}(${message}, ${newContext})`;
  });
}

// Main execution
console.log('Starting logger error fixes...');

const tsFiles = findTsFiles('./src');
let filesFixed = 0;
let totalReplacements = 0;

for (const file of tsFiles) {
  try {
    const content = fs.readFileSync(file, 'utf8');
    const fixedContent = fixLoggerCalls(content);

    if (content !== fixedContent) {
      fs.writeFileSync(file, fixedContent, 'utf8');
      filesFixed++;

      // Count how many replacements were made
      const originalMatches = (content.match(/(this\.logger\.(error|warn|info|debug))\(\s*[^,]+,\s*[^,]+,\s*\{[^}]*\}\s*\)/g) || []).length;
      const fixedMatches = (fixedContent.match(/(this\.logger\.(error|warn|info|debug))\(\s*[^,]+,\s*[^,]+,\s*\{[^}]*\}\s*\)/g) || []).length;
      const replacements = originalMatches - fixedMatches;
      totalReplacements += replacements;

      console.log(`Fixed ${replacements} logger calls in: ${file}`);
    }
  } catch (error) {
    console.error(`Error processing ${file}:`, error.message);
  }
}

console.log(`\nSummary:`);
console.log(`Files processed: ${tsFiles.length}`);
console.log(`Files fixed: ${filesFixed}`);
console.log(`Total logger calls fixed: ${totalReplacements}`);
console.log('\nLogger error fixes completed!');