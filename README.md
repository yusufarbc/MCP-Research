# MCP Protocol Security — LaTeX Paper Workspace

This repository contains a LaTeX project to write an academic paper on Model Context Protocol (MCP) security, along with references and working notes. No historical files are removed; older content is kept under `archive/`.

Quick Start (Windows)
- Install MiKTeX or TeX Live, and VS Code extension "LaTeX Workshop".
- Build the paper:
  - VS Code → Command Palette → LaTeX Workshop: "Recipes" → "latexmk (pdf)", or
  - Terminal: `cd paper && latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex`

Scripts
- Windows: `./scripts/build-paper.ps1 -Open`, `./scripts/clean-paper.ps1`
- POSIX: `bash scripts/build-paper.sh`, `bash scripts/clean-paper.sh`

Project Layout
- `paper/` — manuscript (main.tex, sections, bibliography, figures)
- `references/academic/` — academic PDFs (offline reference)
- `references/resources/` — supporting resources
- `notes/` — working notes (Markdown)
- `archive/` — parked/historical content (not used by the build)
- `CITATIONS.md` — human‑readable citations (URLs and access dates)
- `.vscode/` — settings and tasks (LaTeX Workshop)
- `.github/workflows/` — CI (link check and PDF build)

Citations
- Cite using `paper/bibliography/references.bib` (biblatex + biber).
- Maintain `CITATIONS.md` for quick reference with URLs and access dates.

CI
- Markdown link checking: `.github/workflows/link-check.yml`.
- PDF build: `.github/workflows/latex-build.yml` uploads `paper/main.pdf` as an artifact.

Contributing
- Prefer small, focused PRs; keep sections tidy and cite sources.
- Do not commit LaTeX build artifacts (`.gitignore` excludes common outputs).

