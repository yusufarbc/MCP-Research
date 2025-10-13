# MCP Protokolü Güvenliği — Araştırma Deposu (TR/EN)

Bu depo, Model Context Protocol (MCP) güvenliği üzerine akademik bildiri çalışması için derlenen makaleler, notlar ve görselleri içerir. Amaç: tehdit modeli, zafiyet sınıfları ve savunma stratejilerini derleyip değerlendirerek uygulanabilir rehber oluşturmak.

Hızlı Bağlantılar
- EN akademik PDF’ler: `docs/en/academic/`
- EN kaynaklar (özet/protokol): `docs/en/resources/`
- TR notlar: `docs/tr/notes/`
- Makale taslağı: `paper/outline.md`
- Şekiller: `paper/figures/`
- Atıflar listesi: `CITATIONS.md`
- Link kontrol (CI): `.github/workflows/link-check.yml`

Depo Yapısı
- `docs/en/academic`: arXiv/MDPI vb. makalelerin PDF kopyaları (offline referans)
- `docs/en/resources`: literatür protokolü, özet derlemeleri vb.
- `docs/tr/notes`: Türkçe notlar ve bulgular (ASCII dosya adları)
- `paper/outline.md`: makale bölümleri ve yazım planı
- `paper/figures`: şekiller/diagramlar (boş ise `.gitkeep`)
- `CITATIONS.md`: tekil kaynak envanteri (durum, dosya yolu, erişim tarihi)

Çalışma Akışı
- Yeni yayın ekleme
  - arXiv: dosya adı `docs/en/academic/<arxiv-id>v<rev>.pdf` (örn. `2509.07595v1.pdf`).
  - Yayıncı/DOI: kısa ve anlamlı slug (örn. `electronics-14-03267-v2.pdf`).
  - Aşırı uzun adlardan kaçının (<120 karakter). Windows uzun yol hatalarını önlemek için kısa tutun.
- Atıf ekleme/güncelleme
  - `CITATIONS.md` içine başlık, durum (Present/Web only), yerel yol ve erişim tarihi ekleyin.
- Not ekleme
  - `docs/tr/notes/` altında Markdown dosyaları kullanın; dosya adları ASCII olsun (örn. `google-arastirmasi.md`).

İsimlendirme ve Uyumluluk
- PDF’ler ikili olarak işaretlidir (`.gitattributes`).
- TR dosya adlarında ASCII kullanılır; içerikte Türkçe karakterler serbesttir.
- Gerekirse `git config core.longpaths true` ile uzun yol desteği açılabilir.

Kalite Kontrolleri
- Link kontrolü (CI) push/PR üzerinde çalışır ve Markdown’daki kırık linkleri raporlar.
- Büyük dosyalar yalnızca gerekli olduğunda eklenmelidir (PDF’ler için geçerli).

Katkı
- Küçük ve odaklı PR’lar tercih edilir.
- Dosya yapısı ve adlandırma kurallarına uyun; atıf bilgilerini `CITATIONS.md` ile senkron tutun.

Lisans/Not
- Bu depo yalnızca araştırma ve referans amaçlıdır. İçerdiği PDF’ler, ilgili yayıncı/arXiv lisansları kapsamında değerlendirilmelidir.

