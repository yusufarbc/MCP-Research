#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../paper"
echo "Building paper/main.tex with latexmk..."
latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex

