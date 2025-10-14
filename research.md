# MCP Araştırma Raporu

## İçindekiler
- [1. Özet](#1-özet)
- [2. Giriş](#2-giriş)
- [3. Amacı ve Kullanım Alanları](#3-amacı-ve-kullanım-alanları)
- [4. Mimari ve Veri İletimi](#4-mimari-ve-veri-iletimi)
- [5. Protokol Seviyesi ve Avantajları](#5-protokol-seviyesi-ve-avantajları)
- [6. Açık Kaynak ve Güvenlik](#6-açık-kaynak-ve-güvenlik)
- [7. Tehdit Modeli ve Saldırı Senaryoları](#7-tehdit-modeli-ve-saldırı-senaryoları)
- [8. Güvenlik Önlemleri ve İyi Uygulamalar](#8-güvenlik-önlemleri-ve-iyi-uygulamalar)
- [9. Literatür İncelemesi](#9-literatür-incelemesi)
- [10. Google Scholar Sentezi](#10-google-scholar-sentezi)
- [11. Güncel Olaylar](#11-güncel-olaylar)
- [12. Genişletilmiş Analiz](#12-genişletilmiş-analiz)
- [13. Sonuç](#13-sonuç)
- [14. Kaynaklar ve Bağlantılar](#14-kaynaklar-ve-bağlantılar)

## 1. Özet
- MCP (Model Context Protocol), LLM’ler ile harici araç/veri kaynakları arasında JSON‑RPC tabanlı, istemci‑sunucu mimarisiyle birlikte çalışabilirliği standartlaştırır.
- Kullanım alanları: asistan entegrasyonu, tasarımdan koda otomasyon, kurumsal veri erişimi ve cihaz kontrolü.
- Güvenlikte kritik riskler: araç zehirleme (tool poisoning), prompt enjeksiyonu, açıkta sunucular, tedarik zinciri ve RCE; savunmada sandboxing, en az yetki, kimlik doğrulama, izleme ve denetlenebilirlik öne çıkar.
- Standartlaşma/yönetişim ile performans/maliyet başlıkları, ekosistemin öncelikli çalışma alanlarıdır.

## 2. Giriş
Model Context Protocol (MCP), Anthropic tarafından açık kaynak olarak duyurulan ve LLM tabanlı sistemleri harici araçlar, API’ler ve veri kaynaklarıyla güvenli ve standart biçimde konuşturan bir protokoldür. LLM’lere “USB‑C” benzeri evrensel bir bağlam arayüzü sağlar; yazılım geliştirme süreçlerinde entegrasyon maliyetini düşürürken, güvenlik ve yönetişim gereksinimlerini gündeme taşır.

MCP’nin temel yeniliği, “model” ile “dış dünya” arasında tutarlı ve şemaya bağlı bir arayüz tanımlamasıdır. Bu sayede LLM, yalnızca eğitim verisindeki bilgiye dayanmak yerine, gerçek zamanlı veri kaynaklarına bağlanabilir, iş akışlarını tetikleyebilir ve sonuçları yapılandırılmış şekilde geri alabilir. Araçlar ve kaynaklar, JSON‑RPC üzerinden keşfedilebilir bir sözleşmeyle (schema) sunulur; istemciler bu sözleşmeye göre otomatik bağlanır, yetenekleri listeleyip uygun adımları planlar. Bu yaklaşım, tek tek API entegrasyonları yerine standart bir bağlam katmanı sunarak geliştirici hızını artırır ve bakımı sadeleştirir.

Endüstriyel açıdan MCP, IDE’ler (ör. VS Code/Cursor/Claude Code), chat istemcileri ve kurum içi ajan platformlarıyla hızla bütünleşmektedir. Bu bütünleşme, birden fazla MCP sunucusundan (ör. dosya sistemi, hata izleme, kurumsal veri gölleri) aynı oturumda bağlam çekebilmeyi ve LLM’nin bu bağlamla güvenli eylemler gerçekleştirmesini mümkün kılar. Böylece “metin üretimi”nden “bağlamla zenginleşmiş karar ve eylem” aşamasına geçilir.

<img width="1207" height="799" alt="resim" src="https://github.com/user-attachments/assets/bdf1510b-66f6-427b-9562-f8653e73d66e" />

## 3. Amacı ve Kullanım Alanları
MCP’nin temel amacı, LLM’ler ile harici araçlar/veri kaynakları arasında standart, bağlamsal bir iletişim katmanı sunmaktır. Pratikte bu, LLM’nin hangi araçların erişilebilir olduğunu bilmesi, yeteneklerini (input/output şemalarıyla) anlaması ve bir görevi tamamlamak için doğru araç dizisini planlayıp yürütmesi anlamına gelir. Geliştirici açısından tek tek özel entegrasyonlar yazmak yerine, MCP uyumlu sunucular ekosisteminden seçerek hızlıca değer üretmek mümkündür.

Örnek kullanım alanları:
- Kişisel asistan: Google Takvim/Notion gibi hesaplara bağlanma ve eylem alma.
- Tasarımdan koda: Figma’dan web uygulamasına otomatik dönüşüm.
- Kurumsal veri erişimi: Çoklu veri kaynaklarının tek arayüzden sorgulanması.
- Fiziksel cihazlar: Blender + 3B yazıcı ile doğal dil komutlarıyla tasarım/baskı.

Kurumsal senaryolarda MCP; kimlik, yetki, denetim, kayıt ve politika gereksinimleriyle birlikte ele alınır. Örneğin kurumsal bilgi yönetiminde aynı anda hem raporlama veri ambarına hem de olay/günlük sistemlerine bağlanmak; bir görevi başlatmadan önce kullanıcıdan açık onay almak; yüksek etkili eylemler için “guard” modellerle ikincil teyit almak yaygın uygulamalardır.

## 4. Mimari ve Veri İletimi

<img width="840" height="328" alt="resim" src="https://github.com/user-attachments/assets/ba600697-942e-426f-ad1c-839875ef9772" />

MCP, JSON‑RPC 2.0 tabanlı veri katmanı ile STDIO/HTTP(SSE) taşıma katmanını ayıran iki katmanlı bir yapıya sahiptir. Veri katmanı; araç/ kaynak keşfi, çağrı/yanıt sözleşmeleri, oturum ve bildirim akışlarının anlamsal yapısını tanımlar. Taşıma katmanı, bu mesajların nasıl iletileceğini belirler ve yerel ya da uzak kurulumlara esneklik sağlar.
- İstemci: LLM’i barındıran uygulamanın içinde çalışır; sunucuların araç/kaynaklarını keşfeder.
- Sunucu: Harici veri/işlevleri “araç” arayüzüyle sunan bağımsız süreçtir (dosya sistemi, veritabanı, harici API).
- Çoklu sunucu topolojisi: Aynı host (ör. VS Code) birden fazla MCP sunucusuna eşzamanlı bağlanabilir.
- Taşıma: STDIO (yerel, düşük gecikme, ağ yüzeyi yok) ve HTTP + Server‑Sent Events (uzak, TLS/HTTPS, OAuth 2.0/API anahtarları).

STDIO seçeneği, IDE içinde çalışan yerel araçlarda en düşük gecikmeyi ve minimum saldırı yüzeyini sağlar. HTTP + SSE ise bulut/uzak hizmetlere erişimi standart web altyapılarıyla (TLS, yük dengeleme, OAuth/başlık tabanlı kimlik doğrulama) güvence altına alır. İstemci, bağlı olduğu her sunucudan “yetenek” bilgisini alır, LLM’ye aktarır ve LLM bu yetenekleri kullanarak çok adımlı bir plan oluşturur.

<img width="836" height="512" alt="resim" src="https://github.com/user-attachments/assets/d0cdaa6e-aff0-4d03-ab74-bbd6107c5ff1" />

Örnek veri akışı (özet):
1. Kullanıcı talebi istemciye gelir, istemci bağlı sunucuların yeteneklerini LLM’ye iletir.
2. LLM, amaç doğrultusunda uygun aracı/çağrıyı planlar.
3. İstemci, seçilen aracı sunucudan çağırır; yanıtlar akış (SSE) ile gelebilir.
4. Kritik eylemler için kullanıcı onayı ve politikalara dayalı sınırlamalar uygulanır.
5. Sonuç, LLM üzerinden kullanıcıya döndürülür.

Bu akışta iki temel tasarım ilkesi öne çıkar: (i) plan/uygulama ayrımı (LLM karar verir, istemci güvenlik politikalarına uygun şekilde uygular) ve (ii) denetlenebilirlik (araç çağrılarının ve sonuçlarının günlüklenmesi, geri alınabilirlik). Bildirimler/uyarılar ve kullanıcıdan ek girdi isteme mekanizmaları, çok adımlı görevlerde güvenli etkileşimi sürdürür.

## 5. Protokol Seviyesi ve Avantajları
MCP uygulama katmanında çalışır; bu konum sayesinde mesajlar insan tarafından okunabilir JSON yapılarıyla ifade edilir ve dil/çatı bağımsız SDK’larla kolayca uygulanır. JSON‑RPC 2.0 kullanımı; hata yönetimi, yöntem/parametre sözleşmesi ve çift yönlü mesajlaşmayı basitleştirir.

Taşıma bağımsız tasarım, aynı veri yapılarının yerel STDIO ve uzak HTTP/SSE üzerinden taşınabilmesini sağlar. Böylece bir sunucu önce geliştirici makinesinde test edilebilir, sonra asgari değişiklikle buluta taşınabilir. Güvenlik tarafında ise HTTP ekosisteminin olgun kimlik doğrulama ve şifreleme mekanizmaları (OAuth 2.x, API anahtarları, TLS) doğrudan yeniden kullanılır.

Bu mimari tercihlerin sonucu olarak MCP; ölçeklenebilirlik (çoklu sunucu, çoklu araç), birlikte çalışabilirlik (ortak şema), gözlemlenebilirlik (standart günlükleme) ve bakım kolaylığı (sürümleme/şema evrimi) alanlarında somut faydalar üretir.

## 6. Açık Kaynak ve Güvenlik
MCP’nin açık kaynak doğası iki yönlüdür. Olumlu tarafta; spesifikasyon ve örnek sunucuların açık olması topluluk denetimini, güvenlik açığı geri bildirimlerini ve hızlı düzeltmeleri mümkün kılar. Popüler bileşenlerde dijital imzalar/bütünlük kontrolleri ve şeffaf sürüm notları güveni artırır.

Öte yandan, tedarik zinciri riski gerçektir: kötü niyetli veya ele geçirilmiş paketler aracılığıyla “araç zehirleme” ya da arka kapı yerleştirme girişimleri görülebilir. Bu nedenle sürüm kilitleme (pinning), imzalı yayınların tercih edilmesi, bağımlılık taraması (SBOM/örn. Syft, Grype) ve değişiklik denetimi (CHANGELOG/PROVENANCE) önerilir. Kurumsal ortamlarda, onaylı sunucu/araç katalogları ve izinli kaynak listeleri (allow‑list) ek bir koruma katmanı sağlar.

## 7. Tehdit Modeli ve Saldırı Senaryoları
Komut, prompt ve araç düzeyinde enjeksiyonlar MCP ekosisteminde sık görülen risklerdir. Aşağıdaki örnekler, tipik saldırı vektörlerini ve etkilerini özetler:
- Komut enjeksiyonu: Girdi değerlerinin doğrudan kabuk komutlarına aktarılması (ör. `notify-send` başlığına enjekte edilen komut parçaları) sunucu yetkileriyle keyfi çalıştırmaya yol açabilir. Yerel sunucularda bu, kullanıcı hesabının ele geçirilmesine kadar gidebilir.
- Prompt enjeksiyonu: LLM, zararlı talimatlarla “görevi gizlice genişletmeye” ikna edilerek yetkisiz araç çağrıları yapabilir (ör. istenen işlemin yanında ayrıcalıklı kullanıcı oluşturma). Özellikle otomatik onay akışlarında etki büyüktür.
- Araç zehirleme: Araç açıklamalarına gizli talimatlar yerleştirilmesi veya sonradan güncellemeyle zararlı davranış eklenmesi; LLM’nin açıklamaya güvenmesi nedeniyle veri sızıntısı/yanlış eylem riskini artırır.
- Açıkta kalan sunucular: Kimlik doğrulama/şifreleme olmadan yayınlanan sunucular, doğal dil sorgularıyla hassas verileri sızdırabilir; sayıları azımsanmayacak düzeydedir.
- RCE: Zayıf doğrulama/bağlam izolasyonu, crafted isteklerle uzak kod çalıştırmaya kapı aralayabilir (ör. belirli MCP sunucularındaki CVE’ler).

## 8. Güvenlik Önlemleri ve İyi Uygulamalar
MCP’de güvenlik, taşıma katmanı kontrolleri ile uygulama politikalarının birlikte tasarlanmasıyla sağlanır. Özet başlıkların arkasındaki temel ilkeler:
- Kimlik doğrulama/Yetkilendirme: OAuth 2.0/2.1 akışları ve kısa ömürlü belirteçler; yetkilerin araç/işlev bazında daraltılması (en az yetki) ve kapsam/kuota sınırları.
- Taşıma güvenliği: HTTPS/TLS 1.3; HSTS ve güvenli başlıklar; uzak sunucularda karşılıklı TLS (mTLS) tercih edilebilir.
- Uygulama politikaları: Yüksek etkili eylemlerde kullanıcı onayı (step‑up), korumalı alan (guard model) ve otomasyon kısıtları; sürüm kilitleme ve davranış değişikliği bildirimi.
- Sandboxing/kaynak kısıtları: Docker/VM izolasyonu, sınırlı dosya sistemi/ağ izinleri; rate limiting ve IP tabanlı sınırlar; uzak erişimde allow‑list.
- Girdi/çıktı güvenliği: Girdi doğrulama, kaçış ve çıktı sanitizasyonu; prompt korumaları (örn. Rebuff benzeri katmanlar) ve duyarlı veri maskeleme.
- Tedarik zinciri hijyeni: SBOM (SLSA ile), imzalı yayınlar, Semgrep/Trivy statik tarama; bağımlılık güncellemelerinde onaylı havuz.
- İzleme ve olay yönetimi: OpenTelemetry ile izleme; SIEM entegrasyonu; tehdit istihbaratı beslemeleri; geri alma/runbook’lar.

### Risk ve Savunma Tablosu

| Tehdit Türü           | Açıklama                                 | Savunma Stratejisi                                  |
|-----------------------|------------------------------------------|-----------------------------------------------------|
| Prompt enjeksiyonu    | Zararlı yönergelerle ajan manipülasyonu  | Girdi sanitizasyonu, guard modeller, kullanıcı onayı|
| Araç zehirleme        | Araç açıklamalarına gizli talimat         | Araç tarayıcıları, beyaz liste, sürüm kilitleme     |
| Komut enjeksiyonu     | Filtrelenmemiş girdiden shell çağrıları   | Parametre doğrulama, kaçış, sandbox                 |
| DoS                   | Kaynak tüketimi                           | Rate limiting, kuota, izolasyon                     |
| Gizlilik sızıntısı    | Hassas verinin ifşası                     | Şifreleme (TLS/at‑rest), veri maskesi               |
| Ajan‑ajan enfeksiyonu | Çok ajanlı sistemlerde bulaşma            | A2AS, sınırlandırılmış bağlam, politika sertifikası |

## 9. Literatür İncelemesi

### 9.1 Akademik Çalışmalar (Özet)
- MCP: Landscape, Security Threats, and Future Research Directions — arXiv, 2025‑03
  - Mimari, 4 evre/16 adımlık yaşam döngüsü, 16 senaryoluk tehdit taksonomisi; güçlü yönler ve araştırma yönleri.
- MCP‑Universe: Benchmarking LLMs with Real‑World MCP Servers — arXiv, 2025‑08
  - Gerçek MCP sunucularıyla etkileşimli görev seti; uzun bağlam ve bilinmeyen araç sorunları.
- Automatic Red Teaming LLM‑based Agents with MCP Tools — arXiv, 2025‑09
  - AutoMalTool ile araç zehirleme testleri; sistematik kırmızı takım gereksinimi.
- Advancing Multi‑Agent Systems Through MCP — arXiv, 2025‑04
  - Çok etmenli sistemlerde bağlam paylaşımı ve koordinasyon verimliliği.
- MCP at First Glance: Security & Maintainability of MCP Servers — arXiv, 2025‑06
  - 1.899 sunucuda 8 güvenlik açığı; %5,5 araç zehirleme riski; özel tarama teknikleri.
- MCP‑Guard: A Defense Framework for MCP Integrity — arXiv, 2025‑08
  - Çok katmanlı savunma; MCP‑AttackBench (70k+ saldırı) ve %96 doğruluk.
- A Survey of MCP: Standardizing Context to Enhance LLMs — Preprints.org, 2025‑04
  - İstemci‑sunucu, dinamik araç keşfi; birlikte çalışabilirlik kazanımları, güvenlik/benimseme sorunları.
- A Survey of Agent Interoperability Protocols: MCP, ACP, A2A, ANP — arXiv, 2025‑05
  - Protokol karşılaştırması; MCP’nin güvenli araç çağrısındaki rolü.
- Model Context Protocols in Adaptive Transport Systems — arXiv, 2025‑08
  - Ulaşımda anlamsal birlikte çalışabilirlik ve dinamik veri alışverişi.

### 9.2 Detaylı Literatür Kayıtları
- Konu Başlığı: Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions
  - Kaynak/Kurum & Tarih: arXiv, 2025‑03
  - Bağlantı: https://arxiv.org/abs/2503.23278
  - Türkçe Özet: MCP’nin mimari ve güvenlik boyutlarını inceleyerek dört evre ve 16 faaliyet adımından oluşan bir yaşam döngüsü modeli sunar; 16 tehdit senaryosu taksonomisi, güncel benimsenme ve gelecek araştırma yönleri.
- Konu Başlığı: MCP‑Universe: Benchmarking LLMs with Real‑World MCP Servers
  - Kaynak/Kurum & Tarih: arXiv, 2025‑08
  - Bağlantı: https://arxiv.org/abs/2508.14704
  - Türkçe Özet: Gerçek MCP sunucularıyla etkileşimli görevlerden oluşan benchmark paketi; GPT‑5, Grok‑4, Claude‑4.0‑Sonnet gibi modellerle uzun bağlam ve bilinmeyen araç sorunlarını ölçer.
- Konu Başlığı: Automatic Red Teaming LLM‑based Agents with Model Context Protocol Tools
  - Kaynak/Kurum & Tarih: arXiv, 2025‑09
  - Bağlantı: https://arxiv.org/abs/2509.21011
  - Türkçe Özet: MCP araçlarında araç zehirleme açıklarına odaklanan otomatik kırmızı takım sistemi (AutoMalTool); mevcut savunmaların yetersizliklerini gösterir.
- Konu Başlığı: Advancing Multi‑Agent Systems Through Model Context Protocol
  - Kaynak/Kurum & Tarih: arXiv, 2025‑04
  - Bağlantı: https://arxiv.org/abs/2504.21030
  - Türkçe Özet: Çok etmenli sistemlerde bağlam paylaşımını standartlaştıran MCP mimarisi; kurumsal bilgi yönetimi ve dağıtık problem çözmede performans artışı.
- Konu Başlığı: Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers
  - Kaynak/Kurum & Tarih: arXiv, 2025‑06
  - Bağlantı: https://arxiv.org/abs/2506.13538
  - Türkçe Özet: 1.899 açık kaynak MCP sunucusunda sekiz güvenlik açığı; %7,2 genel güvenlik, %5,5 araç zehirleme riski; MCP’ye özgü tarama teknikleri.
- Konu Başlığı: MCP‑Guard: A Defense Framework for Model Context Protocol Integrity in LLM Applications
  - Kaynak/Kurum & Tarih: arXiv, 2025‑08
  - Bağlantı: https://arxiv.org/abs/2508.10991
  - Türkçe Özet: Statik analiz, derin öğrenme tabanlı dedektör ve LLM “hakem” modülüyle tehditleri %96 doğrulukla yakalayan çok katmanlı savunma; MCP‑AttackBench (70k+ saldırı).
- Konu Başlığı: A Survey of the Model Context Protocol (MCP): Standardizing Context to Enhance LLMs
  - Kaynak/Kurum & Tarih: Preprints.org, 2025‑04
  - Bağlantı: https://www.preprints.org/manuscript/202504.0245/v1
  - Türkçe Özet: Mimari, istemci‑sunucu modeli ve dinamik araç keşfi; birlikte çalışabilirlik kazanımları ve süren güvenlik/benimsenme sorunları.
- Konu Başlığı: A Survey of Agent Interoperability Protocols: MCP, ACP, A2A, and ANP
  - Kaynak/Kurum & Tarih: arXiv, 2025‑05
  - Bağlantı: https://arxiv.org/abs/2505.02279
  - Türkçe Özet: MCP, ACP, A2A ve ANP’nin karşılaştırması; MCP’nin güvenli araç çağrısı ve birlikte çalışabilirlikteki rolü.
- Konu Başlığı: Model Context Protocols in Adaptive Transport Systems: A Survey
  - Kaynak/Kurum & Tarih: arXiv, 2025‑08
  - Bağlantı: https://arxiv.org/abs/2508.19239
  - Türkçe Özet: Akıllı ulaşımda bağlam paylaşımı için MCP’nin potansiyeli; anlamsal birlikte çalışabilirlik ve dinamik veri alışverişinin avantajları.

### 9.3 Sektörel Raporlar ve Bloglar (Detaylı)
- Introducing the Model Context Protocol — Anthropic, 2024‑11 — https://www.anthropic.com/news/model-context-protocol
  - Türkçe Özet: MCP, AI asistanları ile veri kaynakları arasında güvenli bağlantı kuran açık standart; SDK’lar ve örnek sunucular açık kaynak.
- Microsoft Build 2025 — The Age of AI Agents, 2025‑05 — https://blogs.microsoft.com/blog/2025/05/19/microsoft-build-2025-the-age-of-ai-agents-and-building-the-open-agentic-web/
  - Türkçe Özet: GitHub, Copilot Studio, Dynamics 365 ve Azure AI Foundry’de MCP entegrasyonu; OAuth 2.1 tabanlı kimlik doğrulama; standardizasyona katkı.
- Introducing the Data Commons MCP Server — Google Developers, 2025‑09 — https://developers.googleblog.com/en/datacommonsmcp/
  - Türkçe Özet: Kamu veri setlerinin MCP sunucusuyla AI ajanlarına açılması; güvenilir veri erişimi ve halüsinasyonların azalması.
- A New Frontier for Network Engineers — Cisco Blogs, 2025‑05 — https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network
  - Türkçe Özet: Ağ topolojisinin JSON bağlamıyla LLM’e aktarılması; kuruma özgü yapılandırma üretimi.
- What is Model Context Protocol (MCP)? — IBM Think Blog, 2025‑05 — https://www.ibm.com/think/topics/model-context-protocol
  - Türkçe Özet: MCP, AI ile harici servisler arasında evrensel bağlantı katmanı; USB‑C benzeri standart arayüz.
- WTF is MCP and why should publishers care? — Digiday, 2025‑09 — https://digiday.com/media/wtf-is-model-context-protocol-mcp-and-why-should-publishers-care/
  - Türkçe Özet: Yayıncılıkta MCP’nin “AI çağının robots.txt’si” potansiyeli; içerik paylaşım politikaları.

## 10. Google Scholar Sentezi

### 10.1 İncelemenin Yapısı ve Kapsamı
Odak: MCP’nin mimarisi, benimsenme dinamikleri, ampirik performansı, güvenlik ve yönetişim. Tekrarları azaltılmış tematik sentez sunulur.

### 10.2 Temel Tanım ve Mimari
İstemci/sunucu ayrımı, taşıma bağımsız üst katman, araç/kaynak şemaları ve dinamik keşif.

### 10.3 Uygulama, Ölçeklenebilirlik ve Benimseme
Manuel sunucu geliştirme darboğazı → AutoMCP/OpenAPI ile otomasyon; spesifikasyon kalitesi ve araç koordinasyonu yeni engellerdir.

### 10.4 Performans ve Arıza Modları
MCPGAUGE ve benzeri benchmark’larda proaktiflik/gider dengesi; bağlam penceresi sınırlamaları ve çok adımlı görev güvenilirliği.

### 10.5 Alanlara Göre Yoğunluk Analizi
- En Yoğun: Yapay zeka, BT, güvenlik
- Gelişmekte Olan: Ağ mühendisliği, veri bilimi, dijital medya
- Potansiyel: Savunma, biyoteknoloji (erken aşama)

## 11. Güncel Olaylar

### MCP’de Araç Zehirleme Saldırıları (Tool Poisoning Attacks)
Araç tanımlarına gizli zararlı talimatlar enjekte edilerek asistanların manipülasyonu; SSH/API anahtarları ve yetkisiz eylemler.
- İlgili X paylaşımları:
  - https://x.com/Graham_dePenros/status/1976216281033408741 — araç zehirleme PoC/tartışma
  - https://x.com/lbeurerkellner/status/1907075048118059101 — bağlantılı değerlendirme
  - https://x.com/akshay_pachaar/status/1947246782221816087 — saldırı vektörü örneği
  - https://x.com/akshay_pachaar/status/1946926773918429249 — ek örnek/yorum
  - https://x.com/Graham_dePenros/status/1976252021645959302 — olay derlemesi
  - https://x.com/OpenCodeMission/status/1976251957108248856 — topluluk analizi
  - https://x.com/OpenCodeMission/status/1976245247685316721 — ek ipuçları
  - https://x.com/theagentangle/status/1976018568413405335 — kısa özet ve uyarılar

### MCP “Top 25” Zafiyet Raporu
Prompt/komut enjeksiyonu ve kimlik doğrulama eksikleri öne çıkıyor; girdi doğrulama zayıflıkları kritik.
- İlgili X paylaşımları:
  - https://x.com/rryssf_/status/1970524674439422444 — rapor özeti
  - https://x.com/kakarot_ai/status/1975599529681690820 — öne çıkan zafiyetler yorumu
  - https://x.com/lbeurerkellner/status/1907075048118059101 — bağlantılı tartışma

### Açıkta Kalan MCP Sunucuları (Exposed MCP Servers)
492 açık sunucu; çoğunda doğal dil sorgularıyla hassas veriye doğrudan okuma erişimi.
- İlgili X paylaşımları:
  - https://x.com/0x534c/status/1956999290863370481 — KQL avcılığı/tespit önerisi

### Figma MCP Sunucusu Uzak Kod Yürütme (CVE‑2025‑53967)
Zararlı API istekleriyle RCE; prompt enjeksiyonu ve DNS rebinding ile istismar edilebilir. v0.6.3’e güncelleme zorunlu.
- İlgili X paylaşımları:
  - https://x.com/freedomhack101/status/1976288100243607552 — RCE bulgusu/uyarı
  - https://x.com/shah_sheikh/status/1975889172872286316 — CVE detayları
  - https://x.com/TweetThreatNews/status/1975997613221572728 — haber duyurusu

### Sahte npm Paketi Arka Kapı (postmark‑mcp)
E‑postaları gizlice BCC ile yönlendiren paket; 1.600 indirme sonrası kaldırıldı; imzalı kayıtlar ve sandbox izinleri öneriliyor.
- İlgili X paylaşımları:
  - https://x.com/TheHackersNews/status/1972581724992528746 — haber/uyarı
  - https://x.com/theagentangle/status/1976018568413405335 — özet/analiz
  - https://x.com/iamKierraD/status/1975226041309299085 — etki kapsamı

### MCP Güvenlik Kontrol Listesi (SlowMist)
Host/istemci/sunucu katmanlarında riskler; kripto entegrasyonlarında özel tehditler; AI‑blockchain entegrasyonunda temel önlemler.
- İlgili X paylaşımları:
  - https://x.com/SlowMist_Team/status/1911678320531607903 — checklist duyurusu

### MCP Yığınlarında %92 Sömürü Olasılığı
Eklenti zinciri riskleri; CVE analizi; erişim sıkılaştırması ve zayıf halkaların tespiti.
- İlgili X paylaşımları:
  - https://x.com/jfrog/status/1976719975881617553 — analiz/uyarı
  - https://x.com/LouisColumbus/status/1976393986156941725 — endüstri yorumu

### Tehditlerin Sistematik Çalışması
Yaşam döngüsünde 16 tehdit senaryosu; kötü niyetli geliştirici/kullanıcı/dış saldırgan tipleri; faz bazlı güvenlik önlemleri.
- İlgili X paylaşımları:
  - https://x.com/jiqizhixin/status/1976109107804270655 — çalışma özeti
  - https://x.com/vlruso/status/1977603410690977952 — bağlantılı tartışma

### Prompt Enjeksiyonu ve Ajan Güvenliği
Yerel ajanlarda (Cursor, Claude Code) girdi kaynaklı riskler; bağlayıcılar/bellekle artan sızıntı; araçların sandbox’lanması önerisi.
- İlgili X paylaşımları:
  - https://x.com/simonw/status/1909955640107430226 — prompt enjeksiyonu örnek/uyarı
  - https://x.com/karpathy/status/1934657940155441477 — güvenlik notu/görüş
  - https://x.com/Rajan_Medhekar/status/1977601624110768573 — ajan güvenliği yorumu
  - https://x.com/liran_tal/status/1976362229294387584 — güvenlik araştırmacısı yorumu
  - https://x.com/UndercodeUpdate/status/1977524734230229026 — vakalar derlemesi

### Eklenti Kötüye Kullanımı ve Kripto Entegrasyonu
A2A (ajan‑ajan) etkileşimlerinde çoğaltıcı tehdit yüzeyi; sıfır güven ve AI‑odaklı savunma ihtiyacı.
- İlgili X paylaşımları:
  - https://x.com/DarkScorpionAI/status/1977435023147163737 — risk değerlendirmesi
  - https://x.com/vietjovi/status/1977369607015956574 — ek yorum
  - https://x.com/eddy_crypt409/status/1915771464764076441 — kripto entegrasyonu uyarısı

### Gelişmelerden Çıkarımlar
- Güvenlik endişeleri tartışmaları domine ediyor; eklenti yığınlarında yüksek istismar olasılığı.
- Yamalar ve yeni spesifikasyonlar (ör. yetkilendirme güncellemeleri) ilerleme sağlıyor.
- Ekosistem büyüyor; ancak açık sunucular ve kimlik doğrulama boşlukları endişe yaratıyor.

## 12. Genişletilmiş Analiz

### 12.1 Temel Çıkarımlar
- MCP, parçalanmayı azaltan ve pasif açıklamaları aktif bağlam kaynaklarına dönüştüren bir bağlam katmanıdır.
- FaaS üzerinde MCP (AgentX): Esneklik, maliyet ve gecikme avantajları.
- MoE ve tehdit istihbaratı: MITRE ATT&CK, MISP, CVE gibi kaynaklarla bağlam enjeksiyonu.
- Yörüngeler: Proaktif güvenlik tasarımı (16 senaryo/4 saldırgan), performans doğrulama, gelişmiş iş akışı düzenleme, alanlar arası standardizasyon.

### 12.2 Tablo: Temel MCP Araştırmaları (2025 Kümesi)

| Çalışma (Kısaltma)                            | Yayın (Yaklaşık) | Birincil Tema          | Ana Mimari Kavramı                               |
|-----------------------------------------------|------------------|------------------------|---------------------------------------------------|
| MCP – Manzara & Güvenlik (Hou ve ark.)        | 2025‑03          | Tanım & Güvenlik       | Tam Sunucu Yaşam Döngüsü; Tehdit Sınıflandırması  |
| MCPmed – Biyoinformatik çağrısı               | 2025‑07          | Alan Uzmanlığı         | FAIR‑uyumlu makine‑okunur katman                  |
| Help or Hindrance? (MCPGAUGE)                 | 2025‑08          | Ampirik Değerlendirme  | Proaktiflik/Genel Gider Analizi                   |
| AgentX – FaaS üzerinde MCP                    | 2025‑09          | İş Akışı Düzenleme     | FaaS‑barındırmalı MCP Hizmetleri                  |

### 12.3 AI Ajan Güvenlik Protokolleri
- Giriş Doğrulaması ve Sandboxing: Çok faktörlü doğrulama, imtiyaz minimizasyonu, izole yürütme (Docker/VM), kaynak sınırları.
- Şifreleme ve İzleme: TLS 1.3, AES‑256, FPETS (metin dilimleme için biçim‑koruyan şifreleme), FHE; OpenTelemetry ile davranış izleme.
- Protokol‑Spesifik Yaklaşımlar: A2AS (Behavior Certificates, Authenticated Prompts, Security Boundaries, In‑Context Defenses, Codified Policies), A2A protokolleri, guard modelleri.
- Tehdit Modelleri ve Saldırı Vektörleri: 16 tehdit senaryosu; araç/prompt/komut enjeksiyonu; açık sunucular; tedarik zinciri.
- Savunma Stratejileri: Beyaz/siyah liste, rate limiting, sürüm kilitleme, değişiklik izleme, denetlenebilirlik ve geri alma.
- En İyi Uygulamalar ve Çerçeveler: SLSA + SBOM, OWASP AI checklist, adversary eğitimi, just‑in‑time erişim.

### 12.4 Gelecek Yönelimler
Standardizasyonun güçlendirilmesi (A2AS vb.), blockchain tabanlı güven/ceza mekanizmaları, çok ajanlı dağıtık güvenlik; token maliyeti ve model sapmaları gibi sınırlılıklar ile sürekli izleme/güncelleme gereksinimi.

## 13. Sonuç
MCP, LLM tabanlı ajan sistemlerinde standart bağlam paylaşımı, güvenlik ve birlikte çalışabilirlik için merkezî rol üstlenir. Güvenli ve verimli benimseme, sandboxing/en az yetki/denetim ile yönetişim/standardizasyon ve performans‑maliyet optimizasyonunun birlikte ele alınmasını gerektirir.

## 14. Kaynaklar ve Bağlantılar
- Making REST APIs Agent‑Ready: From OpenAPI to MCP — arXiv
- Model Context Protocol (MCP): Manzara, Güvenlik Tehditleri… — arXiv (PDF)
- LiveMCP‑101: Stress‑Testing MCP‑Enabled Systems — arXiv
- MCPToolBench++: A Large‑Scale AI Agent MCP Benchmark — arXiv
- Security of AI Agents — arXiv
- 7 Proven Tips to Secure AI Agents — Jit.io
- AI Agent Security — Google Cloud
- A2AS Framework 1.0 (PDF)
- AI Security Checklist — OWASP
- AI Agent Security: MCP Security — Medium


