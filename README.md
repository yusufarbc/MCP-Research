# MCP Güvenliği — LaTeX Bildiri ve Araştırma Alanı

Bu depo, Model Bağlam Protokolü (MCP) güvenliği üzerine bir akademik bildirinin LaTeX kaynaklarını, başvurulan referansları ve çalışma notlarını içerir. Bu depo bir okul ödevidir; dışarıdan katkı kabul edilmez. Tarihsel içerikler silinmez; gerekirse `archive/` altında saklanır.

## Hızlı Başlangıç
- TeX Live/MiKTeX kurun. VS Code için LaTeX Workshop eklentisini öneririz.
- Derleme seçenekleri:
  - VS Code → Komut Paleti → “LaTeX Workshop: latexmk (pdf)”, veya
  - Terminal: `cd paper && latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex`

## Betikler
- Bildiri derle: `./scripts/build-paper.ps1 -Open` (Windows) veya `bash scripts/build-paper.sh`
- Bildiri temizle: `./scripts/clean-paper.ps1` (Windows) veya `bash scripts/clean-paper.sh`
- Not indeksi üret: `./scripts/generate-notes-index.ps1` veya `bash scripts/generate-notes-index.sh`
- Birleşik notları üret: `./scripts/generate-notes-combined.ps1` veya `bash scripts/generate-notes-combined.sh`

## Notlar
- Klasör: `notes/`
- Not indeksi: `notes/README.md`
- Birleşik özet: `notes/combined.md`
- Örnekler: `notes/literatur.md`, `notes/protokol-arastirmasi.md`, `notes/google-arastirmasi.md`, `notes/x-arastirmasi.md`

Yazım ipuçları
- Dosya adlarında ASCII kullanın; içerikte Türkçe karakterler serbesttir (tüm dosyalar UTF‑8 olmalı).
- İlk satır `# Başlık` olmalı; ilk paragraf kısa özet olarak yazılmalı (indekste 160 karaktere kadar gösterilir).

## Depo Yapısı
- `paper/` — bildiri (main.tex, bölümler, şekiller, kaynakça)
- `references/academic/` — akademik PDF’ler (çevrimdışı referans)
- `references/resources/` — yardımcı kaynaklar
- `notes/` — çalışma notları (bkz. Notlar)
- `archive/` — arşiv/park edilen içerik (derlemede kullanılmaz)
- `CITATIONS.md` — insan okunur atıflar (URL ve erişim tarihleri)
- `.vscode/` — ayarlar ve görevler (LaTeX Workshop + not üretimi)
- `.github/workflows/` — CI (link kontrolü ve PDF derleme)

## Atıflar
- LaTeX’te `paper/bibliography/references.bib` (biblatex + biber) kullanılır.
- Hızlı bakış için `CITATIONS.md` dosyasını URL ve erişim tarihiyle güncel tutun.
