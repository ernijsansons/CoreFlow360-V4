#!/bin/bash
unset CLOUDFLARE_API_TOKEN
cd frontend
npx wrangler pages deploy dist --project-name=coreflow360-frontend --branch=master --commit-dirty=true
