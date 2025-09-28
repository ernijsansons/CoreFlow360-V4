# PowerShell script to fix TypeScript compilation errors systematically
# Fix 2,794 TypeScript errors in systematic phases

Write-Host "Starting systematic TypeScript error fixes..." -ForegroundColor Green

# Phase 1: Fix Logger parameter errors (252 instances)
Write-Host "Phase 1: Fixing logger parameter errors..." -ForegroundColor Yellow

# Find all files with logger errors and fix them
$files = Get-ChildItem -Path "src" -Recurse -Include "*.ts" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match 'logger\.(error|warn|info|debug)\([^,]+,\s*[^,]+,\s*\{[^}]*\}') {
        $_.FullName
    }
}

foreach ($file in $files) {
    Write-Host "Fixing logger calls in: $file"
    $content = Get-Content $file -Raw

    # Fix pattern: logger.error('message', errorVar, { context }) -> logger.error('message', { context, error: errorVar })
    $content = $content -replace 'logger\.(error|warn|info|debug)\(([^,]+),\s*([^,]+),\s*(\{[^}]*\})\)', 'logger.$1($2, { ...$4, error: $3 })'

    # Fix simpler pattern: logger.error('message', string, {}) -> logger.error('message', { error: string })
    $content = $content -replace 'logger\.(error|warn|info|debug)\(([^,]+),\s*([^,{}]+),\s*\{\s*([^}]*)\s*\}\)', 'logger.$1($2, { $4, error: $3 })'

    Set-Content $file $content -NoNewline
}

Write-Host "Phase 1 completed: Logger parameter fixes" -ForegroundColor Green

# Phase 2: Add missing type definitions
Write-Host "Phase 2: Adding missing type definitions..." -ForegroundColor Yellow

# Create WebGPU type definitions
$webgpuTypes = @"
// WebGPU Type Definitions
declare global {
  interface Navigator {
    gpu?: GPU;
  }

  interface WorkerNavigator {
    gpu?: GPU;
  }

  interface Window {
    navigator: Navigator;
  }

  interface GPU {
    requestAdapter(): Promise<GPUAdapter | null>;
  }

  interface GPUAdapter {
    requestDevice(): Promise<GPUDevice>;
  }

  interface GPUDevice {
    createBuffer(descriptor: GPUBufferDescriptor): GPUBuffer;
    createComputePipeline(descriptor: GPUComputePipelineDescriptor): GPUComputePipeline;
    createQuerySet(descriptor: GPUQuerySetDescriptor): GPUQuerySet;
  }

  interface GPUBuffer {
    mapAsync(mode: GPUMapModeFlags): Promise<void>;
    getMappedRange(): ArrayBuffer;
    unmap(): void;
  }

  interface GPUComputePipeline {
    // Add methods as needed
  }

  interface GPUQuerySet {
    // Add methods as needed
  }

  interface GPUBufferDescriptor {
    size: number;
    usage: GPUBufferUsageFlags;
  }

  interface GPUComputePipelineDescriptor {
    // Add properties as needed
  }

  interface GPUQuerySetDescriptor {
    // Add properties as needed
  }

  enum GPUBufferUsage {
    STORAGE = 0x080,
    COPY_SRC = 0x004,
    COPY_DST = 0x008,
  }

  enum GPUMapMode {
    READ = 0x0001,
    WRITE = 0x0002,
  }

  type GPUBufferUsageFlags = number;
  type GPUMapModeFlags = number;
}

export {};
"@

Set-Content "src/types/webgpu.d.ts" $webgpuTypes

Write-Host "Phase 2 completed: Type definitions added" -ForegroundColor Green

# Phase 3: Fix missing exports
Write-Host "Phase 3: Fixing missing exports..." -ForegroundColor Yellow

# Check if shared/errors/index.ts exists and fix it
if (Test-Path "src/shared/errors/index.ts") {
    $errorsIndex = Get-Content "src/shared/errors/index.ts" -Raw
    if ($errorsIndex -notmatch "ErrorCategory|ErrorSeverity") {
        $additionalExports = @"

export enum ErrorCategory {
  SYSTEM = 'system',
  BUSINESS = 'business',
  INTEGRATION = 'integration',
  VALIDATION = 'validation',
  SECURITY = 'security'
}

export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}
"@
        Add-Content "src/shared/errors/index.ts" $additionalExports
    }
}

Write-Host "Phase 3 completed: Missing exports fixed" -ForegroundColor Green

Write-Host "TypeScript error fix script completed!" -ForegroundColor Green
Write-Host "Run 'npx tsc --noEmit' to verify fixes" -ForegroundColor Cyan