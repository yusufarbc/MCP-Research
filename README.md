# MCP-Research

Model Context Protocol (MCP) üzerine araştırma, analiz ve kaynak derlemeleri. Bu depo, MCP’nin mimarisi, güvenlik boyutları, benimsenme dinamikleri ve güncel gelişmeleri hakkında derlenmiş içerikler içerir.

## İçindekiler
- Proje Özeti
- Depo Yapısı
- Hızlı Başlangıç
- Ana Belgeler
- Çalışma Akışı ve Rehber
- Katkı ve İletişim

## Proje Özeti
Bu depodaki ana belge `research.md`, MCP’nin teknik mimarisi, güvenlik tehdit modeli, iyi uygulamalar ve literatür özetiyle birlikte güncel olaylar (X/Twitter bağlantılarıyla) bölümlerini içerir. Akademik ve sektörel kaynaklar Türkçe özetlerle zenginleştirilmiştir.

## Depo Yapısı
- `research.md` — Ana rapor (Özet, Mimari, Tehdit Modeli, İyi Uygulamalar, Literatür, Google Scholar sentezi, Güncel Olaylar ve Genişletilmiş Analiz)
- `paper/` — Makale/çalışma taslakları (varsa)
- `references/` — Atıf/referans notları ve yardımcı materyaller (varsa)
- `archive/` — Arşivlenmiş eski içerikler (ör. önceki README vb.)
- `.vscode/` — Geliştirme ortamı ayarları

## Hızlı Başlangıç
1) Bağımlılıklar: Yalnızca Git yeterlidir.
2) Klonlama: Depo zaten yerelinizde. Güncellemek için normal git akışını izleyin.
3) Okuma: Ana içerik için `research.md` dosyasını açın.

## Ana Belgeler
- `research.md`: Tam rapor ve zenginleştirilmiş “Güncel Olaylar” bölümü (her X linki için tek satırlık bağlam açıklaması eklendi). Dosyanın başında otomatik “İçindekiler” vardır.

Öne çıkan bölümler:
- Mimari ve Veri İletimi: JSON‑RPC, STDIO/HTTP(SSE) taşıma modeli ve çoklu sunucu topolojisi
- Güvenlik: Araç zehirleme, prompt/komut enjeksiyonu, açık sunucular, RCE
- İyi Uygulamalar: Sandboxing, en az yetki, OAuth/TLS, SBOM/SLSA, guard modelleri
- Literatür ve Sektör: Akademik özetler, blog/duyurular ve Türkçe özetler
- Güncel Olaylar: Konu başlıklarına göre gruplanmış X bağlantıları (tek satır özetlerle)


---

