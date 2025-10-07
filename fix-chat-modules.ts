/**
 * Batch fix script for chat module TypeScript errors
 * Run with: npx tsx fix-chat-modules.ts
 */

import * as fs from 'fs'
import * as path from 'path'

// List of files to fix
const filesToFix = [
  'src/modules/chat/file-service.ts',
  'src/modules/chat/streaming-service.ts',
  'src/modules/chat/suggestions-service.ts',
  'src/modules/chat/transcription-service.ts',
  'src/modules/chat/context-service.ts',
  'src/modules/chat/conversation-service.ts'
]

// Transformation rules
const transformations: Array<{ pattern: RegExp, replacement: string }> = [
  // Fix AppError constructor - 3 param (message, code, statusCode)
  { pattern: /throw new AppError\('([^']+)',\s*'([^']+)',\s*(\d+)\)/g, replacement: "throw new AppError('$1', $3, '$2')" },
  { pattern: /throw new AppError\("([^"]+)",\s*"([^"]+)",\s*(\d+)\)/g, replacement: 'throw new AppError("$1", $3, "$2")' },

  // Fix AppError constructor - 2 param without status code (default 500)
  { pattern: /throw new AppError\('([^']+)',\s*'([^']+)'\)/g, replacement: "throw new AppError('$1', 500, '$2')" },
  { pattern: /throw new AppError\("([^"]+)",\s*"([^"]+)"\)/g, replacement: 'throw new AppError("$1", 500, "$2")' },

  // Fix parseInt for string IDs
  { pattern: /\.bind\(([a-zA-Z]+Id)\)\.first\(\)/g, replacement: '.bind($1).first()' },

  // Fix undefined checks for potentially undefined objects
  { pattern: /const uploadResult = await ([^\n]+)\n\s+if \(!uploadResult\)/g, replacement: 'const uploadResult = await $1\n\n      if (!uploadResult)' },

  // Fix string | undefined assignments to string
  { pattern: /language: options\.language\s*$/gm, replacement: 'language: options.language || \'en\'' },
  { pattern: /format: \(options\.format as any\) \|\| 'webm'/g, replacement: 'format: (options.format || \'webm\') as \'wav\' | \'mp3\' | \'webm\' | \'ogg\' | \'m4a\'' },
]

// Process each file
for (const filePath of filesToFix) {
  const fullPath = path.resolve(process.cwd(), filePath)

  if (!fs.existsSync(fullPath)) {
    console.log(`⚠️  File not found: ${filePath}`)
    continue
  }

  let content = fs.readFileSync(fullPath, 'utf-8')
  let modified = false

  for (const { pattern, replacement } of transformations) {
    const before = content
    content = content.replace(pattern, replacement)
    if (content !== before) {
      modified = true
    }
  }

  if (modified) {
    fs.writeFileSync(fullPath, content, 'utf-8')
    console.log(`✅ Fixed: ${filePath}`)
  } else {
    console.log(`ℹ️  No changes: ${filePath}`)
  }
}

console.log('\n✨ Batch fix complete!')
