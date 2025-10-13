# MCP Protocol Security — LaTeX Paper Workspace

This repository is prepared to write an academic paper on Model Context Protocol (MCP) security. It contains a LaTeX project, a curated citations list, and VS Code settings for a smooth authoring experience.

Quick Start (Windows)
- Install a TeX distribution: MiKTeX or TeX Live.
- Install VS Code extension: “LaTeX Workshop”.
- Build the paper:
  - VS Code → Command Palette → LaTeX Workshop: “Recipes” → “latexmk (pdf)”, or
  - Terminal: `cd paper && latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex`

Project Layout
- `paper/main.tex` — main paper file (biblatex+biber)
- `paper/sections/` — per-section content files
- `paper/bibliography/references.bib` — BibTeX database (seeded)
- `paper/figures/` — figures and diagrams
- `CITATIONS.md` — human-readable citations list (links and access dates)
- `.vscode/` — settings and suggestions (LaTeX Workshop)

Citations
- Use `paper/bibliography/references.bib` for citations and `biblatex` (biber) in LaTeX.
- Keep `CITATIONS.md` as a quick, human-readable list with URLs and dates.

Continuous Integration
- Markdown link checking: `.github/workflows/link-check.yml`.
- PDF build (GitHub Actions): `.github/workflows/latex-build.yml` publishes `paper/main.pdf` as an artifact on push/PR.

Contributing
- Prefer small, focused changes. Keep section files tidy and cite sources.
- Do not commit LaTeX build artifacts; `.gitignore` excludes common outputs.

License/Note
- Content is for research and academic purposes. Respect licenses of referenced materials.

