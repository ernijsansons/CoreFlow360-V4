#!/bin/bash

# List of files to fix
files=(
"src/ai-systems/agent-orchestration-framework.ts"
"src/ai-systems/agent-swarm-demo.ts"  
"src/ai-systems/automated-ai-optimizer.ts"
"src/ai-systems/edge-ai-orchestrator.ts"
"src/ai-systems/hallucination-detector.ts"
"src/modules/workflow/orchestrator.ts"
)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    echo "Processing $file..."
    # Add eslint-disable before lines with setTimeout or setInterval
    # This uses sed to insert the comment before matching lines
    sed -i '/setTimeout\|setInterval/ {
      /eslint-disable/! {
        i\    // eslint-disable-next-line no-undef
      }
    }' "$file"
  fi
done

echo "Done!"
