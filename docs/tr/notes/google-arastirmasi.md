# Model Bağlam Protokolü (MCP) Hakkında Kapsamlı Literatür İncelemesi

## Bölüm 1: MCP'ye Giriş (Sentez)

### 1.1 Ajans Paradigması Değişimi ve Entegrasyon Zorluğu

Büyük Dil Modellerinin (LLM) evrimi, yapay zekâ alanında temel bir paradigma değişimini temsil eder ve modelleri pasif metin üretiminin ötesine, gerçek dünyadaki görevleri yerine getirebilen aktif, otonom bir **ajansa** doğru taşır. Bu ajans dönüşümü, **harici araçların çağrılması** için sağlam ve ölçeklenebilir mekanizmalar gerektirir. [1]  
Tarihsel olarak, LLM'lerin harici yeteneklerle entegrasyonu, **entegrasyon zorluğu** nedeniyle engellenmiştir. Bu senaryoda LLM platformları, mevcut harici araçların veya API'lerin her biri için **özel, sabit kodlu bağlamalar** gerektiriyordu. Bu da farklı entegrasyon yollarına yol açarak **yüksek bakım maliyetleri**, yinelemeler ve ekosistem ölçeklendirilmesinde engellere neden oluyordu. [2]

**Model Bağlam Protokolü (MCP)**, bu entegrasyon darboğazını çözmek için geliştirilmiştir. Protokol, çerçeveye özgü, uygulama merkezli araç bağlamalarından; **birleştirilebilir ve dinamik olarak keşfedilebilir ağ hizmetleri**nden oluşan, birlikte çalışabilir bir ekosisteme geçişi öngörür. [2] LLM ile dış dünya arasındaki arayüzü **standartlaştırarak**, MCP yinelenen bakım çabalarını azaltır ve **araç destekli yapay zekâ** için paylaşımlı, ölçeklenebilir bir ekosistem oluşturur. [2]

### 1.2 MCP’yi Tanımlama: “Evrensel Bağlayıcı”

Anthropic tarafından 2024 yılının sonlarında tanıtılan **Model Context Protocol (MCP)**, AI sistemlerinin temel model sınırlarının dışındaki harici verilere, API’lere ve araçlara erişmesi için **tutarlı bir mekanizma** sağlayan, **açık kaynaklı**, **şema odaklı** bir standarttır. [1]  
Genellikle AI için **“evrensel konektör”** olarak nitelendirilen MCP, **gerçek zamanlı karar verme** için tasarlanmıştır ve **ölçeklenebilir, akıllı ajan iş akışları** oluşturmanın temelini oluşturur. [3]

MCP’nin mimarisi, çekirdek LLM akıl yürütme alanı (**istemci**) ile aracın yürütme ortamı (**sunucu**) arasında **katı bir ayrım** uygular. [4] Bu ayrıştırma, mimari esneklik ve modülerlik sağlar: **müşteri/ajan kodunu değiştirmeden** yeni araçlar eklenebilir veya güncellenebilir; LLM’ler talep üzerine yeni sunuculara bağlanarak işlevselliklerini esnek biçimde genişletebilir. [2]

### 1.3 İncelemenin Yapısı ve Kapsamı

Bu inceleme, **2024 sonrası** yayınlanan akademik çalışmalardan elde edilen bulguları sentezlemekte ve **yalnızca MCP’nin mimarisi, benimsenme dinamikleri, ampirik performansı** ve **güvenlik/yönetişim** zorluklarını ele alan kaynaklara odaklanmaktadır. Sonraki bölümlerde, mimari bileşenler ayrıntılandırılacak; uygulama otomasyonundaki atılımlar, uygulama alanları, performans bulguları ve **açık araştırma boşlukları** tartışılacaktır.

---

## Bölüm 2: Önemli Akademik Makaleler (Özet Listesi)

Aşağıdaki özetler, MCP’nin geliştirilmesi, uygulanması ve **ampirik değerlendirmesine** odaklanarak, protokolün anlaşılmasını yönlendiren çekirdek literatürü temsil eder.

- **Özet 1:** Büyük Dil Modelleri (LLM’ler) pasif metin üreticilerinden **aktif ajanlara** evrilmektedir… **[Kaynak: 2]**  
- **Özet 5:** **Araç çağırma**, AI ajanlarının gerçek dünyayla etkileşimi ve karmaşık sorunları çözmesi için kritik bir yetenektir… **[Kaynak: 6]**  
- **Özet (Bulguların Özeti) 2:** MCP için gelecekteki araştırma yönleri; **standardizasyon**, **güven sınırları** ve **sürdürülebilir büyüme**yi güçlendirmeye odaklanır. Güvenlik, ölçeklenebilirlik ve yönetişim sorunları öne çıkar. Dağıtık **sunucu yönetimi**, merkezi bir uyumluluk otoritesinin yokluğunda **yama tutarsızlıkları** ve **yapılandırma sapmaları**na yol açabilir… **[Kaynak: 2]**  
- **Özet 6:** LLM’lerin yetenekleri, çeşitli veri kaynakları veya API sonuçlarını entegre etmek için **işlev çağrıları** ile genişletilir… **[Kaynak: 6]**  
- **Özet (Ekonomik Araştırma Uygulaması) 4:** Bu makale; planlama, araç kullanımı vb. işlevleri yerine getiren otonom **LLM tabanlı sistemleri (AI ajanlarını)** anlaşılır kılar… **[Kaynak: 4]**

---

## Bölüm 3: Araştırmanın Tematik Özeti (Sentez)

### 3.1 Temel Tanım ve Mimari

#### 3.1.1 Mimari Temeller: İstemci–Sunucu Modeli ve Protokol Tasarımı
MCP, temel bir **istemci–sunucu** mimarisi kurar:  
- **MCP İstemcileri (ajan/uygulama):** Sunuculara bağlanır, **yetkinlikleri keşfeder**, çağırır ve sonuçları LLM bağlamına entegre eder. [4]  
- **MCP Sunucuları:** Harici veri kaynaklarıyla **gerçek API etkileşimlerini yürütür**, kimlik doğrulama ve yürütmeyi yönetir. [4]

Protokol, **JSON-RPC 2.0** standardına dayanır; bu seçim **güçlü tipleme**, açık istek/yanıt yaşam döngüsü, **izin katmanları** ve istemci-sunucu **akış mekanizmaları** gibi güvenlik-öncelikli özellikleri kolaylaştırır. [3]

#### 3.1.2 Temel Bileşenler ve Şema Bağımlılığı
MCP, LLM tarafından dinamik keşif ve çağırma için **harici araçların şema ile tanımlanmasına** dayanır. [1] Akademik literatür, bu şemalar için **OpenAPI 2.0/3.0** kullanılmasının etkili olduğunu doğrular. [1]

**LLM**, aracı doğru entegre etmek için **parametreler/girdiler/çıktılar**ın ayrıntılı tanımına ihtiyaç duyar; **MCP sunucusu** bu tanımları kaydeder ve LLM’nin **dosya sistemleri, web tarayıcıları, finansal veriler** gibi özelliklere erişmesini sağlar. [6]

**Tablo 3.1 – MCP Mimari Bileşenleri ve İşlevleri**

| Bileşen                     | Rolü                                                                 | Temel İşlev                                  | Standart/Protokol  | Anahtar Özellik/Kısıtlama                                                                 |
|----------------------------|----------------------------------------------------------------------|----------------------------------------------|--------------------|-------------------------------------------------------------------------------------------|
| **MCP İstemcisi (Ajan)**   | Araçları keşfeder/çağırır; çıktılarını LLM bağlamına entegre eder    | Planlama ve bağlam yönetimi                  | JSON-RPC 2.0       | Bağlam penceresi sınırlıdır; **araç numaralandırma** belirteç uzunluğunu yönetmelidir. [6] |
| **MCP Sunucusu**           | Dış yetenekleri ortaya çıkarır; yürütme ve kimlik doğrulamayı yönetir | Kaynak/araç barındırma                       | OpenAPI-türevi     | Yüksek kaliteli şema gerekir; başlangıçta **manuel iskele** darboğazları görülebilir. [1] |
| **Protokol Tasarımı**      | Standartlaştırılmış araç tanımı ve etkileşimi                         | Birlikte çalışabilir arayüz                   | JSON-RPC 2.0       | Modülerlik, izinler ve **ölçeklenebilir optimizasyon** (önbellek, toplu işleme). [3]      |

### 3.2 Uygulama, Ölçeklenebilirlik ve Benimseme Dinamikleri

#### 3.2.1 Manuel Sunucu Geliştirme Darboğazının Nicelendirilmesi
MCP’nin yayınından sonraki 6 ayda oluşturulan **22.000+ MCP etiketli repo**nun analizinde, **%5’ten azının** işlevsel sunucu uygulamaları içerdiği raporlanmıştır. [1] Birçok proje **tek bakımcı**, **elle şema/kimlik doğrulama** gibi tekrar eden çabalar içerir. [1]

#### 3.2.2 Otomasyon: AutoMCP ve OpenAPI’nin Rolü
**AutoMCP derleyici**, OpenAPI sözleşmelerinden **tam MCP sunucuları** üretebilmektedir. 50 gerçek dünya API’sinde (10+ alan, 5.066 uç nokta) yapılan değerlendirmede:  
- 1.023 araç çağrısından **%76,5**’i ilk denemede başarılı,  
- Küçük düzeltmeler (API başına ~**19 satır** değişiklik) sonrası başarı **%99,9**’a yükselmiştir. [1]

#### 3.2.3 Yeni Benimseme Engeli: **Spesifikasyon Kalitesi**
Otomasyonun başarısı, zorluğun artık **kod üretimi** değil, **OpenAPI sözleşme kalitesi** olduğunu gösterir. Kuruluşlar **API yönetişimine** ve **dokümantasyon doğruluğuna** öncelik vermelidir. [1]

### 3.3 Uygulama Alanları ve Örnekler

#### 3.3.1 Genel Ajan İş Akışları ve Ekosistem Büyümesi
Binlerce bağımsız MCP sunucusu; **GitHub, Slack** gibi hizmetlere erişim sağlar. **MCPToolBench++**, 4.000+ MCP sunucusundan oluşan pazarda veri analizi, dosya işlemleri, finansal hesaplama vb. geniş uygulama alanını doğrular. [6]

#### 3.3.2 Özel Alan: Ekonomik ve Kurumsal Araştırma
MCP, ajanların **kurumsal veritabanlarına** (ör. merkez bankası/özel veri) bağlanıp **sürdürülebilir bağlantılar** kurmasını sağlar; literatür incelemeleri, ekonometrik kodlama ve **özel veri analizi** gibi **özerk araştırma iş akışları** mümkün olur. [4]

### 3.4 Performans: Karşılaştırma ve Analiz

#### 3.4.1 Son Teknoloji Benchmark’lar
- **LiveMCP-101:** 101 gerçek dünya sorgusu, çok-adımlı planlar ve koordinasyon gerektirir. [5]  
- **MCPToolBench++:** Farklı yanıt biçimleri ve araç başarı oranı değişkenliğini adresler; çok alanlı çerçeve sunar. [6]

#### 3.4.2 Bulgular: **Araç Koordinasyon Eksikliği**
En gelişmiş LLM’ler bile **karmaşık çok-adımlı** görevlerde **%60’ın altında** başarı göstermiştir. [5] MCP, erişimi standartlaştırsa da **güvenilir yürütme** için yeterli değildir; sınırlama **planlama/koordinasyon** yeteneklerindedir.

#### 3.4.3 Arıza Modları ve Kaynak Kısıtları

**Tablo 3.2 – MCP Etkin Ajan Yürütmede Gözlemlenen Arıza Modları (LiveMCP-101)**

| Hata Kategorisi        | Örnek Arıza Modu                          | Açıklama                                                                                 | Kaynak |
|------------------------|--------------------------------------------|------------------------------------------------------------------------------------------|--------|
| Araç Koordinasyonu     | **Düşük Başarı**                           | Çok-adımlı eylemlerde başarısızlık; karmaşık koordinasyon gereksinimleri                | [5]    |
| Araç Koordinasyonu     | **Aşırı özgüvenli iç çözüm**               | Ajan, temelli MCP aracını atlayıp iç muhakemeye güvenir; halüsinasyon/erken bitiş       | [5]    |
| Araç Koordinasyonu     | **Gereksinimi göz ardı**                   | Açık gereksinim atlanır; ilgili araç seçilmez                                            | [5]    |
| Uygulama               | **Parametre hataları**                     | Girdi parametreleri yanlış biçimlenir/atlanır                                            | [5]    |
| Ölçeklenebilirlik/Bağlam| **Token verimsizlikleri/sınırları**        | Şema envanteri bağlam penceresini tüketir; planlama/akıl yürütme için alan daralır      | [5,6]  |

---

## Bölüm 4: Sonuç ve Araştırma Boşlukları (Sentez)

### 4.1 Mevcut Durumun Özeti
MCP, **araç etkileşimini standartlaştırma** hedefini büyük ölçüde başarmış; **OpenAPI tabanlı** otomatik sunucu oluşturma ile geliştirici engellerini azaltmıştır. [1] Ekosistem büyümüş; ancak iki kritik alan açık kalmıştır:  
1) **Ajans güvenilirliği** (çok-adımlı görevlerde düşük başarı),  
2) **Ekosistem yönetişimi** (güvenlik/uyumluluk). [2]

### 4.2 Çözülmemiş Zorluklar ve Gelecek Yönelimler

#### 4.2.1 Güvenlik Açıkları ve Güven Sınırları
Dağıtık sunucu yönetimi, merkezi uyumluluk yokluğunda **heterojen uygulamalar** ve **yama tutarsızlıkları**na yol açar. **Zorunlu konfigürasyon doğrulaması**, **otomatik sürüm kontrolü** ve **bütünlük denetimi** gibi teknik yönetişim çözümleri öncelik olmalıdır. [2]

#### 4.2.2 Ölçeklenebilirlik, Parçalanma ve Yönetişim
Bağlam penceresi kısıtı, **araç envanteri** ↔ **akıl yürütme derinliği** arasında ödünleşim yaratır. **Dinamik, bağlamsal araç keşfi** ve **şema sıkıştırma** araştırmaları önceliklidir. [6] Düşük güvenilirlik, yüksek riskli kurumsal alanlarda etik, güvenlik ve yasal sonuçları büyütür; **adalet**, **veri sızıntısı savunması** ve **hesap verebilirlik** odaklı yönetişim şarttır. [2,4]

### Kaynaklar (Bölüm 1–4)
1. **Making REST APIs Agent-Ready: From OpenAPI to MCP** – arXiv (13 Eki 2025) → https://arxiv.org/abs/2507.16044  
2. **Model Bağlam Protokolü (MCP): Manzara, Güvenlik Tehditleri…** – arXiv (13 Eki 2025) → https://arxiv.org/pdf/2503.23278  
3. **Model Bağlam Protokolü (MCP) Nedir | Nasıl Çalışır** – Kodexo Labs (13 Eki 2025) → https://kodexolabs.com/what-is-model-context-protocol-mcp/  
4. **AI Agents for Economic Research** – NBER Working Paper (13 Eki 2025) → https://www.nber.org/system/files/working_papers/w34202/w34202.pdf  
5. **LiveMCP-101: Stress-Testing MCP-Enabled Systems** – arXiv (13 Eki 2025) → https://arxiv.org/abs/2508.15760  
6. **MCPToolBench++: A Large-Scale AI Agent MCP Benchmark** – arXiv (13 Eki 2025) → https://arxiv.org/abs/2508.07575

---

# Model Bağlam Protokolü (MCP): LLM Entegrasyonu, Ajans Sistemleri ve Araç Kullanımı Standardizasyonunda Rolünün Uzman Analizi

## 1. Giriş: Otonom Yapay Zekâ için Temel Katman Olarak MCP
LLM’lerin harici kaynaklar ve araçlarla **dinamik arayüz** oluşturması için standart, güvenilir bir yöntem eksikti. **MCP**, AI modelleri ile harici kaynak/araçlar arasında **birleşik, çift yönlü iletişim katmanı** tanımlayarak bu boşluğu doldurur. MCP, **parçalanmayı** azaltır ve **pasif işlev açıklamalarını** **aktif bağlam kaynaklarına** dönüştürür. 2025’teki yayın kümeleri, MCP’nin **acil bir endüstri tepkisi** olarak olgunlaştığını gösterir. [2]

## 2. Mimari Gereklilik: Dağıtım Modelleri ve Gelişmiş Sistem Entegrasyonu

### 2.1 FaaS ile Barındırılan MCP Hizmetleri
**AgentX** çalışması, MCP sunucularının **FaaS** üzerinde barındırılmasının başarı, gecikme ve maliyet açısından avantajlarını gösterir; **patlama** tarzı kullanım profilleriyle doğal uyum sağlar. [9]

### 2.2 MoE Mimarilerinde MCP
**Uzman Karışımı (MoE)** senaryolarında MCP, **MITRE ATT&CK, MISP, CVE** gibi tehdit istihbaratı kaynaklarını bağlayarak **semantik bağlam farkındalığı** sağlar; endüstriyel ortamlarda uyarlanabilir karar vermeyi güçlendirir.

**Tablo 1 – Temel MCP Araştırmaları (2025 Kümesi): Zaman Çizelgesi ve Odak**

| Çalışma (Kısaltma)                                   | Yayın (Yaklaşık) | Birincil Tema            | Ana Mimari Kavramı                              |
|------------------------------------------------------|------------------|--------------------------|--------------------------------------------------|
| MCP – Manzara & Güvenlik (Hou ve ark.)               | 2025-03          | Tanım & Güvenlik         | Tam Sunucu Yaşam Döngüsü; Tehdit Sınıflandırması |
| MCPmed – Biyoinformatik Çağrısı                      | 2025-07          | Alan Uzmanlığı           | FAIR-uyumlu makine-okunur katman                 |
| Help or Hindrance? (MCPGAUGE)                        | 2025-08          | Ampirik Değerlendirme    | Proaktiflik/Genel Gider Analizi                  |
| AgentX – FaaS üzerinde MCP                            | 2025-09          | İş Akışı Düzenleme       | FaaS-barındırmalı MCP Hizmetleri                 |

## 3. Yörünge I: Proaktif Güvenlik Tasarımı ve Tehdit Sınıflandırması
MCP ile **çift yönlü iletişim**, yeni saldırı yüzeyleri getirir. Literatür, 4 saldırgan türü ve **16 tehdit senaryosu** ile kapsamlı bir **tehdit modeli** sunar ve yaşam döngüsü-özgü **uygulanabilir önlemler** önerir. [2]

## 4. Yörünge II: Performans Doğrulama ve “Araç Kullanımının Engeli”
**MCPGAUGE**, 160 prompt/25 veri seti/≈20k API çağrısı ile 6 ticari LLM ve 30 MCP araç paketinde 4 boyutta ölçüm yapar: **Proaktiflik, Uyum, Etkinlik, Genel Gider**. Bulgular, MCP’nin mimari yararlarının **otomatik performans artışı** garantilemediğini; **uyum/proaktiflik** düşüklüğü ve **ek yük** sorunlarının kritik olduğunu gösterir. (LLM eğitimi ve ince ayarlarının MCP-uyumlu optimizasyonu önerilir.)

**Tablo 2 – MCP Entegrasyonu: Avantajlar, Riskler ve Performans Boyutları**

| Kategori     | Gözlemlenen Fayda                                           | Risk/Sınırlama                                  | İlgili Boyut     |
|--------------|--------------------------------------------------------------|--------------------------------------------------|------------------|
| Mimari       | Birleşik/dinamik araç keşfi; FaaS ölçeklenebilirliği; MoE    | Tam yaşam döngüsü yönetimi (16 faaliyet)         | **Etkinlik**     |
| İşlevsel     | Anlamsal bağlam; dinamik veri yorumlama; özerklik            | Uyum eksikliği; düşük proaktiflik                | **Proaktiflik/ Uyumluluk** |
| Operasyonel  | Tekrarlanabilirlik; müdahalesiz varlık yönetimi               | Hesaplama maliyeti ve gecikme                    | **Genel Gider**  |
| Güvenlik     | Dış tehdit istihbaratı entegrasyonu                           | 16 tehdit senaryosuna maruziyet                  | —                |

## 5. Yörünge III: Gelişmiş Ajan İş Akışı Düzenleme
**AgentX** modeli (sahne tasarımcısı, planlayıcı, yürütücü) ile **FaaS-barındırmalı MCP** araçları; pratik uygulamalarda **başarı, gecikme, maliyet** açısından avantaj sağlar. **GenAI + MCP + Applied ML** birlikteliği, sağlık/finans/robotik gibi alanlarda **bağlam duyarlı otonomi** için temel sunar. [6,9]

## 6. Yörünge IV: Alanlar Arası Uzmanlaşma ve Standardizasyon

### 6.1 **MCPmed**: Biyomedikal Araştırmada FAIR İlkeleri
GEO, STRING, UCSC Cell Browser gibi **insan-merkezli** web sunucularının **LLM-okunabilirliğini** MCP ile artırma çağrısı; **yapılandırılmış, makine-işlenebilir katman** ile otomasyon/tekrarlanabilirlik/birlikte çalışabilirlik kazancı. [7]

### 6.2 Kritik Altyapı Varlık Keşfi
ICS’de **deterministik araçların** sınırlamalarına karşı; MoE + MCP ile **tehdit istihbaratı** (MITRE ATT&CK, MISP, CVE) entegrasyonu ve **bağlam zenginleştirme** üzerinden uyarlanabilir keşif ve güvenlik duruşu güçlendirme. [11]

**Tablo 3 – Alan Spesifik Zorluklarda MCP’nin Rolü**

| Etki Alanı              | MCP Öncesi Sınırlama                                   | MCP Çözümü/Çerçevesi                               | Temel MCP İşlevi                              |
|-------------------------|---------------------------------------------------------|-----------------------------------------------------|-----------------------------------------------|
| Biyoinformatik/Araştırma| LLM-okunabilirliğini sınırlayan insan-merkezli sunucular| **MCPmed**; hafif “breadcrumb” ve şablonlar         | FAIR uyumlu **makine-işlenebilir erişim** [7] |
| Kritik Altyapı (ICS)    | Bağlamsal muhakemeden yoksun deterministik araçlar     | MoE + MCP ile tehdit istihbaratı entegrasyonu       | **Bağlam enjeksiyonu** (MISP/CVE bağlama)     |

## 7. Google Scholar Özet Koleksiyonu (Markdown)

- **Model Bağlam Protokolü (MCP): Genel Durum, Güvenlik Tehditleri ve Gelecek Yönelimler** — *Hou ve ark.*  
  **Özet:** MCP, birleşik, çift yönlü… **[Kaynak: 2]**

- **AgentX: FaaS-Barındırılan MCP Hizmetleri ile Sağlam Ajan İş Akışları** — *Tokal ve ark.*  
  **Özet:** GenAI çeşitli alanları dönüştürmüştür… **[Kaynak: 9]**

- **Help or Hindrance? Rethinking LLMs Empowered with MCP** — *Song ve ark.*  
  **Özet:** MCP, LLM’lerin erişimini sağlar… **[Kaynak: 10]**

- **MCPmed: LLM-Odaklı Keşif için MCP-Destekli Biyoinformatik Web Hizmetleri Çağrısı** — *Flotho ve ark.*  
  **Özet:** Biyoinformatik web sunucuları… **[Kaynak: 7]**

- **Integrating GenAI & MCP with Applied ML for Advanced Agentic AI Systems** — *Bhandarwar*  
  **Özet:** GenAI, MCP ve Uygulamalı ML… **[Kaynak: 12]**

## 8. Sentez ve Gelecekteki Standardizasyon Zorlukları

MCP, birinci nesil ajan sistemlerinin **ölçeklenebilirlik** ve **bağlam yönetimi** sınırlarını aşmak için gerekli mimari olgunluğu sağlar; **otomasyon** (AutoMCP), **FaaS dağıtımı** (AgentX) ve **alan-özgü adaptasyonlar** (MCPmed) bunu destekler.  
Kalıcı iki zorunluluk:  
- **Güvenlik Riski Yönetimi:** 16 tehdit senaryosu ve 4 saldırgan türü; yaşam döngüsü-özgü önlemler, **politika yönetimi** ve **denetim izleri** şart. [2]  
- **Verimlilik ve Model Uyumluluğu:** MCPGAUGE, **uyum/proaktiflik** ve **ek yük** sorunlarına işaret eder; **MCP-uyumlu eğitim** ve **etkileşim maliyeti azaltımı** önceliklidir. [10]

**Sürdürülebilir Büyüme:** MCPmed ve ICS örnekleri, protokolün **uyarlanabilirliğini** gösterir. Gelecek çalışmalar, **standardizasyonun güçlendirilmesi**, **güven sınırlarının iyileştirilmesi** ve **LLM performansının MCP’ye optimize edilmesi**ne odaklanmalıdır.

### Ek Kaynaklar (Bölüm 1’deki [1–6] numaralandırmasına ek)

7. **MCPmed: A Call for MCP-Enabled Bioinformatics Web Services** – arXiv → https://arxiv.org/abs/2507.08055  
8. **MCPmed (HTML sürüm)** – arXiv → https://arxiv.org/html/2507.08055v1  
9. **AgentX: Toward Robust Agent Workflow with FaaS-Hosted MCP Services** – arXiv → https://arxiv.org/abs/2509.07595  
10. **Help or Hindrance? Rethinking LLMs Empowered with MCP** – arXiv → https://arxiv.org/abs/2508.12566  
11. **Asset Discovery in Critical Infrastructures: An LLM-Based Approach** – MDPI → https://www.mdpi.com/2079-9292/14/16/3267  
12. **Integrating Generative AI & MCP with Applied ML…** – ResearchGate → (PDF bağlantısı kullanıcı paylaşımlı)

> **Not:** Bazı bağlantılar üçüncü taraf barındırıcılar üzerinde olabilir ve erişim kısıtları/URL değişimleri içerebilir.

