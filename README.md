# MCP Protokolü Güvenliği — LaTeX Bildiri Çalışma Alanı

Bu depo, Model Bağlam Protokolü (MCP) güvenliği üzerine bir akademik bildiriyi hazırlamak için oluşturulmuş LaTeX projesini, başvurulan kaynakları ve çalışma notlarını içerir. Tarihsel içerikler silinmez; eski materyaller `archive/` altında tutulur.

Hızlı Başlangıç (Windows)
- MiKTeX veya TeX Live kurun, VS Code için "LaTeX Workshop" eklentisini yükleyin.
- Derleme:
  - VS Code → Komut Paleti → LaTeX Workshop: "Recipes" → "latexmk (pdf)", veya
  - Terminal: `cd paper && latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex`

Betikler
- Windows: `./scripts/build-paper.ps1 -Open`, `./scripts/clean-paper.ps1`
- POSIX: `bash scripts/build-paper.sh`, `bash scripts/clean-paper.sh`
 - Not indeksi: `./scripts/generate-notes-index.ps1` veya `bash scripts/generate-notes-index.sh`
 - Birleşik notlar: `./scripts/generate-notes-combined.ps1` veya `bash scripts/generate-notes-combined.sh`

Depo Yapısı
- `paper/` — bildiri (main.tex, bölümler, kaynakça, şekiller)
- `references/academic/` — akademik PDF’ler (çevrimdışı referans)
- `references/resources/` — yardımcı kaynaklar
- `notes/` — çalışma notları (Markdown), bkz. `notes/README.md` ve `notes/combined.md`
- `archive/` — arşiv/park edilen içerik (derlemede kullanılmaz)
- `CITATIONS.md` — insan okunur atıflar (URL ve erişim tarihleri)
- `.vscode/` — ayarlar ve görevler (LaTeX Workshop)
- `.github/workflows/` — CI (link kontrolü ve PDF derleme)

Atıflar
- LaTeX’te `paper/bibliography/references.bib` (biblatex + biber) kullanın.
- Hızlı bakış için `CITATIONS.md` dosyasını URL ve erişim tarihiyle güncel tutun.

CI
- Markdown link kontrolü: `.github/workflows/link-check.yml`.
- PDF derleme: `.github/workflows/latex-build.yml` `paper/main.pdf` çıktısını artifact olarak yükler.

Katkı
- Küçük ve odaklı PR’lar tercih edilir; bölümleri düzenli tutun ve atıf yapın.
- LaTeX derleme çıktıları commit edilmemelidir (`.gitignore` yaygın çıktıları hariç tutar).
# Notlar Dizini

Bu dizin, çalışma sürecindeki notların kısa tanımlarını ve bağlantılarını içerir. Önerilen okuma sırası aşağıdadır.

- Google Araştırması — `notes/google-arastirmasi.md`
  - MCP mimarisi, güvenlik, tool poisoning, A2A ve tedarik zinciri risklerine dair arama öncülleri ve bağlantılar.

- Literatür — `notes/literatur.md`
  - MCP üzerine mimari, benimseme ve güvenlik temalarını özetleyen Türkçe literatür notları.

- Protokol Araştırması — `notes/protokol-arastirmasi.md`
  - Roller, mesaj akışları, güven sınırları; birincil dokümanlara/örneklere giden bağlantılar.

- X Araştırması — `notes/x-arastirmasi.md`
  - X/Twitter ve bloglardan derlenen tehditler ve vakalar: açık sunucular, tool poisoning, CVE’ler.

İpuçları
- Notları Markdown başlıkları ve tarih içerecek şekilde tutun.
- Dosya adlarında ASCII kullanın; içerikte Türkçe karakterler serbesttir.
- Gündem dışı notları `archive/` altına taşıyarak bu listeyi güncel tutun.

