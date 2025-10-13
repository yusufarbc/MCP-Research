#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../paper"
echo "Cleaning LaTeX build artifacts..."
latexmk -C

