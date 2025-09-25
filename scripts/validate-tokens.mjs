import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message, type = 'info') {
  const prefix = {
    info: `${colors.cyan}ℹ${colors.reset}`,
    success: `${colors.green}✓${colors.reset}`,
    warning: `${colors.yellow}⚠${colors.reset}`,
    error: `${colors.red}✖${colors.reset}`,
  }[type] || '';

  console.log(`${prefix} ${message}`);
}

function validateTokenStructure(tokens) {
  const errors = [];
  const warnings = [];

  // Check required top-level categories
  const requiredCategories = ['global', 'semantic'];
  const optionalCategories = ['$themes', 'dark', '$metadata', 'component'];

  for (const category of requiredCategories) {
    if (!tokens[category]) {
      errors.push(`Missing required category: ${category}`);
    }
  }

  // Check global tokens structure
  if (tokens.global) {
    const expectedGlobalCategories = ['colors', 'typography', 'spacing', 'radius', 'shadows', 'effects'];
    for (const category of expectedGlobalCategories) {
      if (!tokens.global[category]) {
        warnings.push(`Missing expected global category: global.${category}`);
      }
    }
  }

  // Check semantic tokens structure
  if (tokens.semantic) {
    const expectedSemanticCategories = ['colors', 'typography', 'spacing'];
    for (const category of expectedSemanticCategories) {
      if (!tokens.semantic[category]) {
        warnings.push(`Missing expected semantic category: semantic.${category}`);
      }
    }
  }

  return { errors, warnings };
}

function validateTokenReferences(tokens, path = '', visited = new Set()) {
  const errors = [];

  function resolveReference(ref, currentPath) {
    // Handle token references like {global.colors.primary}
    const match = ref.match(/^\{(.+)\}$/);
    if (!match) return { valid: true, value: ref };

    const refPath = match[1];

    // Check for circular references
    if (visited.has(refPath)) {
      return {
        valid: false,
        error: `Circular reference detected: ${currentPath} -> ${refPath}`
      };
    }

    // Navigate to the referenced token
    const parts = refPath.split('.');
    let current = tokens;

    for (const part of parts) {
      if (!current[part]) {
        return {
          valid: false,
          error: `Invalid reference: ${refPath} (missing: ${part})`
        };
      }
      current = current[part];
    }

    // If the resolved value is also a reference, resolve it recursively
    if (current.value && typeof current.value === 'string' && current.value.startsWith('{')) {
      visited.add(refPath);
      const result = resolveReference(current.value, refPath);
      visited.delete(refPath);
      return result;
    }

    return { valid: true, value: current };
  }

  function traverse(obj, currentPath = '') {
    for (const [key, value] of Object.entries(obj)) {
      const fullPath = currentPath ? `${currentPath}.${key}` : key;

      if (value && typeof value === 'object') {
        if (value.value && typeof value.value === 'string' && value.value.includes('{')) {
          // This is a token with a reference
          const result = resolveReference(value.value, fullPath);
          if (!result.valid) {
            errors.push(result.error);
          }
        } else {
          // Continue traversing
          traverse(value, fullPath);
        }
      }
    }
  }

  traverse(tokens);
  return errors;
}

function findDuplicateTokens(tokens) {
  const duplicates = [];
  const tokenPaths = new Set();

  function traverse(obj, path = '') {
    for (const [key, value] of Object.entries(obj)) {
      const fullPath = path ? `${path}.${key}` : key;

      if (value && typeof value === 'object') {
        if (value.value !== undefined) {
          // This is a token
          if (tokenPaths.has(fullPath)) {
            duplicates.push(fullPath);
          } else {
            tokenPaths.add(fullPath);
          }
        } else {
          // Continue traversing
          traverse(value, fullPath);
        }
      }
    }
  }

  traverse(tokens);
  return duplicates;
}

function validateTokenTypes(tokens) {
  const warnings = [];
  // W3C Design Tokens spec + Tokens Studio compatible types
  const validTypes = [
    'color',
    'typography',
    'spacing',
    'dimension',
    'shadow',
    'border',
    'opacity',
    'fontFamily',
    'fontSize',      // W3C spec
    'fontWeight',
    'lineHeight',    // W3C spec
    'letterSpacing', // W3C spec
    'number',
    'duration',
    'cubicBezier'
  ];

  function traverse(obj, path = '') {
    for (const [key, value] of Object.entries(obj)) {
      const fullPath = path ? `${path}.${key}` : key;

      if (value && typeof value === 'object') {
        if (value.value !== undefined && value.type) {
          // Check if type is valid
          if (!validTypes.includes(value.type)) {
            warnings.push(`Unknown token type "${value.type}" at ${fullPath}`);
          }
        } else if (value.value === undefined) {
          // Continue traversing
          traverse(value, fullPath);
        }
      }
    }
  }

  traverse(tokens);
  return warnings;
}

async function main() {
  const isCI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

  if (!isCI) {
    console.log(`${colors.bright}Design Token Validation${colors.reset}\n`);
  }

  const tokenFilePath = path.join(__dirname, '..', 'design-system', 'design-tokens.json');

  // Check if file exists
  if (!fs.existsSync(tokenFilePath)) {
    log(`Token file not found: ${tokenFilePath}`, 'error');
    process.exit(1);
  }

  // Read and parse tokens
  let tokens;
  try {
    const fileContent = fs.readFileSync(tokenFilePath, 'utf8');
    tokens = JSON.parse(fileContent);
    log('Token file parsed successfully', 'success');
  } catch (error) {
    log(`Failed to parse token file: ${error.message}`, 'error');
    process.exit(1);
  }

  // Run validations
  let hasErrors = false;

  // 1. Validate structure
  log('\nValidating token structure...');
  const structureResult = validateTokenStructure(tokens);

  if (structureResult.errors.length > 0) {
    hasErrors = true;
    structureResult.errors.forEach(error => log(error, 'error'));
  } else {
    log('Token structure is valid', 'success');
  }

  if (structureResult.warnings.length > 0) {
    structureResult.warnings.forEach(warning => log(warning, 'warning'));
  }

  // 2. Validate references
  log('\nValidating token references...');
  const referenceErrors = validateTokenReferences(tokens);

  if (referenceErrors.length > 0) {
    hasErrors = true;
    referenceErrors.forEach(error => log(error, 'error'));
  } else {
    log('All token references are valid', 'success');
  }

  // 3. Check for duplicates
  log('\nChecking for duplicate tokens...');
  const duplicates = findDuplicateTokens(tokens);

  if (duplicates.length > 0) {
    duplicates.forEach(dup => log(`Duplicate token found: ${dup}`, 'warning'));
  } else {
    log('No duplicate tokens found', 'success');
  }

  // 4. Validate token types
  log('\nValidating token types...');
  const typeWarnings = validateTokenTypes(tokens);

  if (typeWarnings.length > 0) {
    typeWarnings.forEach(warning => log(warning, 'warning'));
  } else {
    log('All token types are valid', 'success');
  }

  // Summary
  const stats = {
    'Total tokens': Object.keys(tokens).length,
    'Structure errors': structureResult.errors.length,
    'Structure warnings': structureResult.warnings.length,
    'Reference errors': referenceErrors.length,
    'Duplicate tokens': duplicates.length,
    'Type warnings': typeWarnings.length,
  };

  if (!isCI) {
    console.log(`\n${colors.bright}Validation Summary${colors.reset}`);
    console.log('─'.repeat(40));

    for (const [key, value] of Object.entries(stats)) {
      const color = value > 0 && key.includes('error') ? colors.red :
                    value > 0 && key.includes('warning') ? colors.yellow :
                    colors.green;
      console.log(`${key}: ${color}${value}${colors.reset}`);
    }
  }

  // Write validation results to JSON for CI
  const validationResults = {
    timestamp: new Date().toISOString(),
    stats,
    errors: [
      ...structureResult.errors.map(e => ({ type: 'structure', message: e })),
      ...referenceErrors.map(e => ({ type: 'reference', message: e }))
    ],
    warnings: [
      ...structureResult.warnings.map(w => ({ type: 'structure', message: w })),
      ...typeWarnings.map(w => ({ type: 'type', message: w })),
      ...duplicates.map(d => ({ type: 'duplicate', message: `Duplicate token: ${d}` }))
    ]
  };

  const resultsPath = path.join(__dirname, '..', 'design-system', 'validation-results.json');
  fs.writeFileSync(resultsPath, JSON.stringify(validationResults, null, 2));

  if (hasErrors) {
    log('\nValidation failed with errors', 'error');
    process.exit(1);
  } else if (structureResult.warnings.length > 0 || typeWarnings.length > 0 || duplicates.length > 0) {
    log('\nValidation passed with warnings', 'warning');
    if (isCI) {
      process.exit(0); // Don't fail CI for warnings
    }
  } else {
    log('\nValidation passed successfully!', 'success');
  }
}

main().catch(error => {
  log(`Unexpected error: ${error.message}`, 'error');
  process.exit(1);
});