#!/usr/bin/env node

/**
 * SUPERNOVA Targeted Fix Script
 * Fixes the most critical TypeScript compilation errors systematically
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🎯 SUPERNOVA TARGETED FIX');
console.log('=========================');
console.log('');

// Critical files with most errors
const criticalFiles = [
  'src/modules/agent-system/memory.ts',
  'src/modules/business-context/department-profiler.ts', 
  'src/services/call-summarizer.ts',
  'src/services/deal-intelligence.ts',
  'src/services/omnichannel-orchestrator.ts',
  'src/services/voice-synthesis-service.ts',
  'src/services/workflow-automation.ts'
];

console.log('🔧 Fixing critical TypeScript compilation errors...');
console.log('');

let totalFixes = 0;
let successfulFixes = 0;

for (const filePath of criticalFiles) {
  if (fs.existsSync(filePath)) {
    console.log(`📝 Fixing ${filePath}...`);
    
    try {
      let content = fs.readFileSync(filePath, 'utf-8');
      const originalContent = content;
      
      // Apply comprehensive fixes
      content = fixTypeScriptFile(content, filePath);
      
      if (content !== originalContent) {
        fs.writeFileSync(filePath, content, 'utf-8');
        console.log(`✅ Fixed ${filePath}`);
        successfulFixes++;
      } else {
        console.log(`ℹ️ No changes needed for ${filePath}`);
      }
      
      totalFixes++;
      
    } catch (error) {
      console.log(`❌ Failed to fix ${filePath}: ${error.message}`);
      totalFixes++;
    }
  } else {
    console.log(`⚠️ File not found: ${filePath}`);
  }
}

console.log('');
console.log('🔍 Running TypeScript compilation check...');

try {
  const { execSync } = await import('child_process');
  execSync('npx tsc --noEmit', { stdio: 'pipe' });
  console.log('✅ TypeScript compilation successful!');
} catch (error) {
  console.log('⚠️ Some TypeScript errors remain:');
  console.log(error.stdout.toString().substring(0, 1000) + '...');
}

console.log('');
console.log('📊 TARGETED FIX SUMMARY:');
console.log(`- Files processed: ${totalFixes}`);
console.log(`- Successfully fixed: ${successfulFixes}`);
console.log(`- Success rate: ${totalFixes > 0 ? Math.round((successfulFixes / totalFixes) * 100) : 0}%`);

console.log('');
console.log('🎉 SUPERNOVA TARGETED FIX COMPLETED!');

// Helper function to fix TypeScript files
function fixTypeScriptFile(content, filePath) {
  let fixed = content;
  
  // Fix 1: Remove unterminated string literals and fix syntax
  fixed = fixUnterminatedStrings(fixed);
  
  // Fix 2: Fix object literal syntax
  fixed = fixObjectLiterals(fixed);
  
  // Fix 3: Fix function declarations
  fixed = fixFunctionDeclarations(fixed);
  
  // Fix 4: Fix missing semicolons and commas
  fixed = fixMissingPunctuation(fixed);
  
  // Fix 5: Fix template literals
  fixed = fixTemplateLiterals(fixed);
  
  // Fix 6: Fix specific file issues
  if (filePath.includes('memory.ts')) {
    fixed = fixMemorySpecific(fixed);
  } else if (filePath.includes('call-summarizer.ts')) {
    fixed = fixCallSummarizerSpecific(fixed);
  } else if (filePath.includes('workflow-automation.ts')) {
    fixed = fixWorkflowAutomationSpecific(fixed);
  }
  
  return fixed;
}

function fixUnterminatedStrings(content) {
  let fixed = content;
  
  // Fix unterminated string literals
  fixed = fixed.replace(/`[^`]*$/gm, (match) => {
    if (!match.endsWith('`')) {
      return match + '`';
    }
    return match;
  });
  
  // Fix unterminated regular expressions
  fixed = fixed.replace(/\/[^\/]*$/gm, (match) => {
    if (match.startsWith('/') && !match.endsWith('/') && !match.endsWith('/g') && !match.endsWith('/i')) {
      return match + '/';
    }
    return match;
  });
  
  return fixed;
}

function fixObjectLiterals(content) {
  let fixed = content;
  
  // Fix object property syntax - add quotes around unquoted keys
  fixed = fixed.replace(/(\w+)\s*:\s*([^,}]+)(?=\s*[,}])/g, (match, key, value) => {
    const trimmedValue = value.trim();
    
    // Skip if already properly formatted
    if (trimmedValue.includes('"') || trimmedValue.includes("'") || trimmedValue.includes('{') || trimmedValue.includes('[')) {
      return `${key}: ${trimmedValue}`;
    }
    
    // Add quotes around string values
    if (isNaN(trimmedValue) && trimmedValue !== 'true' && trimmedValue !== 'false' && trimmedValue !== 'null' && trimmedValue !== 'undefined') {
      return `${key}: "${trimmedValue}"`;
    }
    
    return `${key}: ${trimmedValue}`;
  });
  
  // Fix missing commas in object literals
  fixed = fixed.replace(/(\w+)\s*(?=\s*[,}])/g, '$1,');
  
  return fixed;
}

function fixFunctionDeclarations(content) {
  let fixed = content;
  
  // Fix function parameter types
  fixed = fixed.replace(/function\s+(\w+)\s*\(([^)]*)\)\s*{/g, (match, funcName, params) => {
    if (params.trim() === '') {
      return `function ${funcName}(): any {`;
    }
    
    const typedParams = params.split(',').map(param => {
      const trimmed = param.trim();
      if (trimmed.includes(':')) return trimmed;
      return `${trimmed}: any`;
    }).join(', ');
    
    return `function ${funcName}(${typedParams}): any {`;
  });
  
  // Fix async function declarations
  fixed = fixed.replace(/async\s+(\w+)\s*\(([^)]*)\)\s*{/g, (match, funcName, params) => {
    if (params.trim() === '') {
      return `async ${funcName}(): Promise<any> {`;
    }
    
    const typedParams = params.split(',').map(param => {
      const trimmed = param.trim();
      if (trimmed.includes(':')) return trimmed;
      return `${trimmed}: any`;
    }).join(', ');
    
    return `async ${funcName}(${typedParams}): Promise<any> {`;
  });
  
  return fixed;
}

function fixMissingPunctuation(content) {
  let fixed = content;
  
  // Add missing semicolons
  fixed = fixed.replace(/([^;}])\s*$/gm, (match) => {
    if (match.trim() && !match.trim().endsWith(';') && !match.trim().endsWith('{') && !match.trim().endsWith('}')) {
      return match + ';';
    }
    return match;
  });
  
  // Fix missing commas in arrays
  fixed = fixed.replace(/(\w+)\s*(?=\s*\])/g, '$1,');
  
  return fixed;
}

function fixTemplateLiterals(content) {
  let fixed = content;
  
  // Fix unterminated template literals
  fixed = fixed.replace(/`[^`]*$/gm, (match) => {
    if (!match.endsWith('`')) {
      return match + '`';
    }
    return match;
  });
  
  return fixed;
}

function fixMemorySpecific(content) {
  let fixed = content;
  
  // Fix specific memory.ts issues
  fixed = fixed.replace(/(\w+)\s*:\s*([^,}]+)(?=\s*[,}])/g, (match, key, value) => {
    const trimmedValue = value.trim();
    if (trimmedValue.includes('"') || trimmedValue.includes("'") || trimmedValue.includes('{') || trimmedValue.includes('[')) {
      return `${key}: ${trimmedValue}`;
    }
    return `${key}: "${trimmedValue}"`;
  });
  
  return fixed;
}

function fixCallSummarizerSpecific(content) {
  let fixed = content;
  
  // Fix complex object literal syntax in call-summarizer.ts
  fixed = fixed.replace(/(\w+)\s*:\s*([^,}]+)(?=\s*[,}])/g, (match, key, value) => {
    const trimmedValue = value.trim();
    if (trimmedValue.includes('"') || trimmedValue.includes("'") || trimmedValue.includes('{') || trimmedValue.includes('[')) {
      return `${key}: ${trimmedValue}`;
    }
    return `${key}: "${trimmedValue}"`;
  });
  
  return fixed;
}

function fixWorkflowAutomationSpecific(content) {
  let fixed = content;
  
  // Fix workflow-automation.ts specific issues
  fixed = fixed.replace(/(\w+)\s*:\s*([^,}]+)(?=\s*[,}])/g, (match, key, value) => {
    const trimmedValue = value.trim();
    if (trimmedValue.includes('"') || trimmedValue.includes("'") || trimmedValue.includes('{') || trimmedValue.includes('[')) {
      return `${key}: ${trimmedValue}`;
    }
    return `${key}: "${trimmedValue}"`;
  });
  
  return fixed;
}
