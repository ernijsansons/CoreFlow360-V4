# Fix all Cloudflare workers-types imports
$files = Get-ChildItem -Recurse src -Include "*.ts"

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw
    if ($content -match "@cloudflare/workers-types") {
        Write-Host "Fixing imports in $($file.FullName)"
        
        # Calculate relative path depth
        $depth = ($file.FullName -replace [regex]::Escape((Get-Location).Path + "\src\"), "" -split "\\").Count - 1
        $relativePath = "../" * $depth + "cloudflare/types/cloudflare"
        
        # Replace the import
        $content = $content -replace "from '@cloudflare/workers-types'", "from '$relativePath'"
        $content = $content -replace "import \{ ([^}]+) \} from '@cloudflare/workers-types';", "import type { `$1 } from '$relativePath';"
        $content = $content -replace "import type \{ ([^}]+) \} from '@cloudflare/workers-types';", "import type { `$1 } from '$relativePath';"
        
        Set-Content $file.FullName $content -NoNewline
    }
}

Write-Host "Import fixing completed!"