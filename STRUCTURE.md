# Repository Structure and Conventions

Purpose: Prepare and maintain an academic paper on MCP security with clear separation between manuscript, references, and notes — without removing historical material.

Top‑level layout
- `paper/` — LaTeX manuscript (main.tex, sections, figures, bibliography)
- `references/academic/` — Academic PDFs (arXiv/MDPI/etc.) for offline reference
- `references/resources/` — Misc resources (protocols, abstract collections)
- `notes/` — Working notes (Markdown)
- `archive/` — Parked or historical content kept for reference (not used by build)
- `scripts/` — Build/clean helper scripts (Windows and POSIX)
- `.github/workflows/` — CI (link check, LaTeX build)
- `CITATIONS.md` — Human‑readable citations list with links and access dates

Conventions
- Keep manuscript content in `paper/sections/*.tex` and cite via `paper/bibliography/references.bib`.
- Store PDFs in `references/academic/`. Use concise filenames (avoid extremely long names).
- Keep active notes in `notes/`. Anything not actively used can be moved to `archive/`.
- Do not delete historical files; move to `archive/` if you need to declutter.

Build and Tools
- Windows: `./scripts/build-paper.ps1 -Open` and `./scripts/clean-paper.ps1`
- POSIX: `bash scripts/build-paper.sh` and `bash scripts/clean-paper.sh`
- CI produces a PDF artifact from `paper/main.tex` on push/PR.

