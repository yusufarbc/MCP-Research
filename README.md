# MCP Protokolü Güvenliği — LaTeX Bildiri Çalışma Alanı

Bu depo, Model Bağlam Protokolü (MCP) güvenliği üzerine bir akademik bildiriyi hazırlamak için oluşturulmuş LaTeX projesini, başvurulan kaynakları ve çalışma notlarını içerir. Tarihsel içerikler silinmez; eski materyaller `archive/` altında tutulur.

## Hızlı Başlangıç (Windows)
- MiKTeX veya TeX Live kurun, VS Code için “LaTeX Workshop” eklentisini yükleyin.
- Derleme seçenekleri:
  - VS Code → Komut Paleti → LaTeX Workshop: “Recipes” → “latexmk (pdf)”, veya
  - Terminal: `cd paper && latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex`

## Betikler
- Bildiri derle: `./scripts/build-paper.ps1 -Open` (Windows) veya `bash scripts/build-paper.sh`
- Bildiri temizle: `./scripts/clean-paper.ps1` (Windows) veya `bash scripts/clean-paper.sh`
- Not indeksi üret: `./scripts/generate-notes-index.ps1` veya `bash scripts/generate-notes-index.sh`
- Birleşik notlar üret: `./scripts/generate-notes-combined.ps1` veya `bash scripts/generate-notes-combined.sh`

## Notlar (Gezinme)
- Not indeksi: `notes/README.md`
- Birleşik özet: `notes/combined.md`

- Literatür: `notes/literatur.md` — MCP’ye dair mimari, benimseme ve güvenlik temaları özetleri.
- Protokol Araştırması: `notes/protokol-arastirmasi.md` — roller, mesaj akışları, güven sınırları.
- Google Araştırması: `notes/google-arastirmasi.md` — arama öncülleri ve bağlantılar.
- X Araştırması: `notes/x-arastirmasi.md` — tehditler ve vakalar (açık sunucular, tool poisoning, CVE’ler).

Not yazım ipuçları
- Dosya adlarında ASCII kullanın; içerikte Türkçe karakterler serbesttir.
- Başlık ve tarih ekleyin; ilk paragrafı kısa özet olarak yazın (indekste 160 karaktere kadar gösterilir).

## Depo Yapısı
- `paper/` — bildiri (main.tex, bölümler, kaynakça, şekiller)
- `references/academic/` — akademik PDF’ler (çevrimdışı referans)
- `references/resources/` — yardımcı kaynaklar
- `notes/` — çalışma notları (bkz. “Notlar”)
- `archive/` — arşiv/park edilen içerik (derlemede kullanılmaz)
- `CITATIONS.md` — insan okunur atıflar (URL ve erişim tarihleri)
- `.vscode/` — ayarlar ve görevler (LaTeX Workshop + not üretimi)
- `.github/workflows/` — CI (link kontrolü ve PDF derleme)

## Atıflar
- LaTeX’te `paper/bibliography/references.bib` (biblatex + biber) kullanın.
- Hızlı bakış için `CITATIONS.md` dosyasını URL ve erişim tarihiyle güncel tutun.