#!/bin/sh
set -eu
umask 077
cd /workspace
export npm_config_cache=/tmp/npm-cache
export PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright
if [ -n "${DEPENDENCIES_JSON:-}" ]; then
  printf '%s' "$DEPENDENCIES_JSON" > /tmp/dependencies.json
  node -e 'const fs=require("fs"); const d=JSON.parse(fs.readFileSync("/tmp/dependencies.json")); fs.writeFileSync("/workspace/package.json", JSON.stringify({private:true,dependencies:d}));'
  npm install --ignore-scripts --no-audit --no-fund --package-lock=false
fi
exec node /workspace/index.js
