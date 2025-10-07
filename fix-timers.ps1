# Fix setTimeout and setInterval issues by adding (as any) casts

$files = @(
"src/ai-systems/agent-orchestration-framework.ts",
"src/ai-systems/agent-swarm-demo.ts",
"src/ai-systems/automated-ai-optimizer.ts",
"src/ai-systems/edge-ai-orchestrator.ts",
"src/ai-systems/hallucination-detector.ts"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "Processing $file"
        
        # Read content
        $content = Get-Content $file -Raw
        
        # Fix setTimeout patterns
        $content = $content -replace '(?<!as any\)\()setTimeout\(', '(setTimeout as any)('
        $content = $content -replace 'new Promise\(resolve => setTimeout\(', 'new Promise(resolve => (setTimeout as any)('
        
        # Fix setInterval patterns  
        $content = $content -replace '(?<!as any\)\()setInterval\(', '(setInterval as any)('
        
        # Write back
        Set-Content -Path $file -Value $content -NoNewline
    }
}

Write-Host "Done!"
