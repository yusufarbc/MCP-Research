# Model Bağlam Protokolü (MCP) Hakkında Önemli Bilgiler

#### 1. MCP'de Araç Zehirleme Saldırıları (Tool Poisoning Attacks)
MCP sunucularında araç tanımlarına gizli zararlı talimatlar enjekte edilerek AI asistanlarının manipüle edilmesi, SSH anahtarları ve API anahtarları gibi hassas verilerin sızdırılmasına yol açan kritik bir tehdit. Saldırılar, kullanıcı onayı altında gizli eylemler gerçekleştirerek veri dışa aktarımı veya yetkisiz erişim sağlıyor. Geniş çapta tartışılan bu saldırı türü, MCP'nin tedarik zinciri risklerini vurguluyor.

İlgili X postları:
- https://x.com/Graham_dePenros/status/1976216281033408741
- https://x.com/lbeurerkellner/status/1907075048118059101
- https://x.com/akshay_pachaar/status/1947246782221816087
- https://x.com/akshay_pachaar/status/1946926773918429249
- https://x.com/Graham_dePenros/status/1976252021645959302
- https://x.com/OpenCodeMission/status/1976251957108248856
- https://x.com/OpenCodeMission/status/1976245247685316721
- https://x.com/theagentangle/status/1976018568413405335

#### 2. MCP Üst 25 Zafiyet Raporu (Top 25 Vulnerabilities Report)
MCP'de tespit edilen 25 kritik zafiyetin 18'i kolay sömürülebilir olarak sınıflandırılıyor; prompt enjeksiyonu, komut enjeksiyonu ve eksik kimlik doğrulaması gibi temel güvenlik hataları, web geliştirme standartlarının gerisinde kalıyor. Rapor, AI ajanlarının veritabanı ve dosya sistemi erişimlerinde input doğrulama eksikliğini vurgulayarak üretim ortamlarında acil güvenlik disiplini gerekliliğini belirtiyor.

İlgili X postları:
- https://x.com/rryssf_/status/1970524674439422444
- https://x.com/kakarot_ai/status/1975599529681690820
- https://x.com/lbeurerkellner/status/1907075048118059101 (bağlantılı tartışma)

#### 3. Açıkta Kalan MCP Sunucuları (Exposed MCP Servers)
Trend Micro tarafından tespit edilen 492 açık MCP sunucusu, kimlik doğrulaması veya şifreleme olmadan çevrimiçi erişime maruz; %90'ı doğal dil sorguları ile hassas verilere (bulut kaynakları, müşteri bilgileri) doğrudan okuma erişimi sağlıyor. KQL sorguları ile bu sunucuların avlanması öneriliyor, ciddi veri sızıntısı riski taşıyor.

İlgili X postları:
- https://x.com/0x534c/status/1956999290863370481

#### 4. Figma MCP Sunucusu Uzak Kod Yürütme Zafiyeti (Figma MCP RCE Vulnerability)
Figma'nın MCP sunucusunda (CVE-2025-53967) tespit edilen kritik zafiyet, zararlı API istekleri yoluyla uzak kod yürütmeye izin veriyor; AI prompt enjeksiyonu ve DNS rebinding ile sömürülebilir. v0.6.3 sürümüne güncelleme zorunlu, aksi halde sistemsel uzlaşma mümkün.

İlgili X postları:
- https://x.com/freedomhack101/status/1976288100243607552
- https://x.com/shah_sheikh/status/1975889172872286316
- https://x.com/TweetThreatNews/status/1975997613221572728

#### 5. Sahte npm Paketi Arka Kapı Olayı (Fake npm Package Backdoor - postmark-mcp)
postmark-mcp adlı sahte npm paketi, her e-postayı gizlice BCC ile saldırgana yönlendirerek 1.600 indirmeden sonra kaldırıldı; faturalar ve şifre sıfırlamaları gibi verileri sızdırdı. MCP tedarik zinciri saldırılarını yansıtıyor, imzalı kayıtlar ve sandbox izinleri öneriliyor.

İlgili X postları:
- https://x.com/TheHackersNews/status/1972581724992528746
- https://x.com/theagentangle/status/1976018568413405335
- https://x.com/iamKierraD/status/1975226041309299085

#### 6. MCP Güvenlik Kontrol Listesi (MCP Security Checklist)
SlowMist tarafından yayınlanan MCP güvenlik rehberi, ana bilgisayar, istemci ve sunucu katmanlarında riskleri kapsıyor; çoklu MCP ve kripto para entegrasyonlarında özel tehditler vurgulanıyor. AI ve blockchain ekosistemlerinin güvenli entegrasyonu için temel önlemler sunuyor.

İlgili X postları:
- https://x.com/SlowMist_Team/status/1911678320531607903

#### 7. MCP Yığınlarında %92 Sömürü Olasılığı (92% Exploit Probability in MCP Stacks)
MCP eklenti yığınlarında %92 sömürü olasılığı, kurumsal güvenlik kör noktalarını artırıyor; CVEs analizi ve savunma stratejileri, erişim sıkılaştırması ve zayıf noktaları tespit etmeyi öneriyor. Eklenti zincirleri büyük ölçekli sömürülere yol açabiliyor.

İlgili X postları:
- https://x.com/jfrog/status/1976719975881617553
- https://x.com/LouisColumbus/status/1976393986156941725

#### 8. MCP Tehditlerinin Sistematik Çalışması (Systematic Study of MCP Threats)
MCP yaşam döngüsünde 16 tehdit senaryosu tanımlayan çalışma, kötü niyetli geliştiriciler, kullanıcılar ve dış saldırganları kapsıyor; gerçek dünya vakalarıyla desteklenen faz bazlı güvenlik önlemleri öneriliyor. Interoperabilite için güvenli benimseme yol haritası sunuyor.

İlgili X postları:
- https://x.com/jiqizhixin/status/1976109107804270655
- https://x.com/vlruso/status/1977603410690977952 (bağlantılı tartışma)

#### 9. MCP Prompt Enjeksiyonu ve Ajan Güvenliği (MCP Prompt Injection and Agent Security)
MCP'de prompt enjeksiyonu, güvenilmeyen girdilere maruz kalan araçlardan kaynaklanıyor; özellikle yerel ajanlarda (Cursor, Claude Code) risk yüksek. Bağlayıcılar ve bellek özellikleriyle birleşince veri sızıntısı artıyor, araçları sandbox'lama öneriliyor.

İlgili X postları:
- https://x.com/simonw/status/1909955640107430226
- https://x.com/karpathy/status/1934657940155441477
- https://x.com/Rajan_Medhekar/status/1977601624110768573
- https://x.com/liran_tal/status/1976362229294387584
- https://x.com/UndercodeUpdate/status/1977524734230229026

#### 10. MCP Sunucularında Kötüye Kullanım ve Kripto Entegrasyonu Tehditleri (MCP Plugin Abuse and Crypto Integration Risks)
MCP eklenti kötüye kullanımı ve kripto entegrasyonları, yeni güvenlik riskleri getiriyor; A2A (ajan-ajan) etkileşimlerinde çoğaltıcı tehdit yüzeyi oluşuyor. AI odaklı savunmalar ve sıfır güven mimarisi zorunlu.

İlgili X postları:
- https://x.com/DarkScorpionAI/status/1977435023147163737
- https://x.com/vietjovi/status/1977369607015956574
- https://x.com/eddy_crypt409/status/1915771464764076441


- **Güvenlik Endişeleri Tartışmaları Domine Ediyor**: Araştırmalar, MCP'nin araç zehirleme saldırılarına karşı savunmasız olduğunu gösteriyor. Bu saldırılarda, kötü niyetli sunucular araç açıklamalarına zararlı komutlar yerleştirerek veri sızdırılmasına veya yetkisiz eylemlere yol açabiliyor. Kanıtlar, yüksek istismar olasılıklarına işaret ediyor. Raporlar, eklenti yığınlarında %92'ye varan risk olduğunu gösteriyor, ancak tarayıcılar ve kontrol listeleri gibi savunma araçları ortaya çıkmaya başlıyor.
- **Son Zamanlarda Ortaya Çıkan Güvenlik Açıkları ve Sömürüler**: Prompt enjeksiyonu ve eksik kimlik doğrulama gibi kritik kusurların, sahte npm paketlerinin e-postalara arka kapı açması gibi gerçek senaryolarda sömürüldüğü muhtemel görünüyor. Topluluk analizleri, eski web güvenlik uygulamalarıyla paralellikler kurarak, bu kusurların kolayca sömürülebilir olduğunu vurguluyor.
- **Yamalar, Düzeltmeler ve Güncellemeler**: Gelişmeler, yeni spesifikasyonlar (örneğin, yetkilendirmeyi geliştiren 2025-06-18 sürümü) ve zehirleme veya rug pull'ları tespit eden MCP tarayıcıları gibi güvenlik araçları dahil olmak üzere, devam eden iyileştirmelere işaret etmektedir. Claude, Cursor ve ChatGPT gibi platformlarla entegrasyonlar, işlevselliği genişletirken riskleri azaltmayı amaçlamaktadır.
- **Güncel Gelişmeler ve Entegrasyonlar**: Protokol, Spring AI, MuleSoft ve blok zinciri platformları (ör. Rootstock, Cardano) gibi ekosistemlerde desteklenerek AI ajanları için yaygın olarak benimsenmektedir. Bu, birlikte çalışabilirliği teşvik etmekte ancak açık sunucular ve kimlik doğrulama boşlukları konusunda endişeleri artırmaktadır.
- **Topluluk ve Resmi Tartışmalar**: Tartışmalar, araştırmacıların ve şirketlerin faydalar ve riskler konusunda dengeli görüşleri vurgulayan analizleriyle, heyecan ve ihtiyatın karışımı bir havayı yansıtmaktadır. Resmi duyurular, AI araç bağlantıları için standardizasyona odaklanırken, tartışmalar AI tabanlı ekonomilerin potansiyelini kabul etmekle birlikte, test edilmemiş uygulamalar konusunda uyarıda bulunmaktadır.
#### MCP'ye Genel Bakış
Model Context Protocol (MCP), AI modelleri ve harici araçlar arasında çift yönlü iletişim için açık bir standart görevi görür ve parçalanmış AI ekosistemlerini birleştirir. Claude Desktop ve Cursor gibi uygulamalarda uygulanır ve sorunsuz entegrasyonlar sağlar, ancak eklenti kötüye kullanımı gibi yeni riskler getirir. Son zamanlarda yayınlanan yazılar, ajanların veri kaynaklarına zahmetsizce bağlandığı ajans AI'daki rolünü vurgulamaktadır, ancak bu durum güvenlik kör noktalarını artırmaktadır.
#### Önemli Güvenlik Açıkları
Araç zehirlenmesi kritik bir sorun olarak öne çıkmaktadır: Kötü niyetli MCP sunucuları, kullanıcı onaylarını atlayarak ve zararsız görünüm altında zararlı eylemler gerçekleştirerek gizli komutlar enjekte edebilir. Diğer açıklar arasında, açıkta kalan sunucular (çevrimiçi olarak 492 tane bulunmuştur), komut enjeksiyonu ve bozuk kimlik doğrulama yer almaktadır ve bunlar genellikle “kolay” olarak değerlendirilmektedir. Sahte npm paketinin e-postaları çalması gibi gerçek hayattaki olaylar, bu konunun aciliyetini vurgulamaktadır.
#### Savunmadaki Gelişmeler
Tehditlere karşı koyma çabaları arasında, ana bilgisayar, istemci ve sunucu katmanlarını kapsayan güvenlik kontrol listeleri ve saldırıları tespit etmek için özel tarayıcılar bulunmaktadır. Yamalar, Figma'nın MCP sunucusunda uzaktan kod yürütülmesine izin veren gibi belirli güvenlik açıklarını giderir. Vulnerablemcp[.]info gibi topluluk kaynakları, saldırıları anlamaya ve önlemeye yardımcı olmak için saldırı özetleri sunar.
#### Ekosistem Büyümesi
MCP, blok zincirinden (ör. DeMCP_AI pazarı) geliştirici araçlarına (ör. tarayıcı kontrolü için Chrome DevTools) kadar çeşitli platformlarla entegre olmaktadır. Güncellemeler, güvenli ölçeklendirme için daha iyi yetkilendirme gibi kurumsal özellikleri geliştirir. Ancak tartışmalar, mevcut API'lerle uyumsuzluk ve uzaktan kurulumlarda kimlik doğrulama zorlukları gibi sınırlamaları vurgulamaktadır.
---
Model Context Protocol (MCP), AI alanında önemli bir açık standart olarak ortaya çıkmış ve büyük dil modelleri (LLM'ler) ile harici araçlar veya veri kaynakları arasında kesintisiz çift yönlü iletişimi kolaylaştırmıştır. AI ekosistemlerindeki parçalanmayı gidermek için tasarlanan MCP, tak ve çalıştır entegrasyonlarını mümkün kılarak AI ajanlarının gerçek zamanlı verilere erişmesine, eylemleri gerçekleştirmesine ve özel kodlama olmadan çeşitli sistemlerle etkileşime girmesine olanak tanır. Genellikle AI için TCP/IP'ye benzetilen bu protokol, masaüstü ortamlarındaki uygulamaları (ör. Claude Desktop, Cursor), blok zinciri pazarlarını ve kurumsal yığınları destekleyerek geliştirme karmaşıklığını azaltır ve modüler AI iş akışlarının önünü açar. Ancak, hızlı benimsenmesi önemli güvenlik sorunlarını gündeme getirmiştir. Geçtiğimiz yıl yapılan tartışmalar, umut verici düzeltmeler, güncellemeler ve topluluk odaklı analizlerin yanı sıra, erken web geliştirme tuzaklarını anımsatan güvenlik açıklarını ortaya çıkarmıştır.
#### Evrim ve Teknik Temeller
MCP'nin temel mimarisi üç katman etrafında döner: model (işlemlerin ve verilerin standart temsilleri), bağlam (ağ parametreleri gibi çevresel ayrıntılar) ve protokol (eylemleri oluşturma ve gönderme mantığı). Bu modülerlik, OpenAI, Anthropic ve Google gibi sağlayıcıların LLM'leri arasında birlikte çalışabilirliği destekler. 2025-06-18 güncellemesi gibi son spesifikasyonlar, kurumsal kullanım için geliştirilmiş yetkilendirme, elde etme mekanizmaları ve kaynak bağlantıları gibi iyileştirmeler getirerek güvenli, ölçeklenebilir AI sistemleri oluşturmayı kolaylaştırmıştır. Teknik tartışmalar, MCP'nin yerel bir masaüstü protokolü (kamu trafiği için SSE ile stdio üzerinde çalışan) olarak ortaya çıkışını vurgulamaktadır. Bu, kimlik doğrulama engellerini (başlıklar veya çerezler için yerel destek eksikliği) ve bunları gidermek için AI API ağ geçitlerinin yükselişini açıklamaktadır. Entegrasyonlar, blok zincirine (ör. zincir üzerinde geliştirme için Rootstock MCP Sunucusu, işlem oluşturma için Cardano) ve geliştirme araçlarına (ör. tarayıcı hata ayıklama için Chrome DevTools, AI'nın DOM'u incelemesine, UI testleri çalıştırmasına ve ekran görüntüleri ile düzeltmeleri doğrulamasına olanak tanır) kadar uzanmaktadır. Kurumsal bağlamlarda, Spring AI ve MuleSoft MCP gibi çerçeveler HTTP, zamanlama ve hata toleransı için bildirimsel API'leri desteklerken, Amazon Bedrock AgentCore dakikalar içinde üretime hazır AI ajanları sağlar.
#### Güvenlik Açıkları ve Güvenlik Kusurları
Güvenlik tartışmaları MCP ile ilgili içeriği domine ederken, araç zehirlenmesi kritik bir tehdit olarak ortaya çıkmaktadır. Bu saldırılarda, kötü niyetli sunucular araç açıklamalarına zararlı talimatlar yerleştirir ve AI asistanları bunları komut istemlerine dahil eder, böylece kullanıcılar görünüşte zararsız talepleri onaylarken veri sızıntıları (ör. SSH anahtarları, API anahtarları) gibi yetkisiz eylemler gerçekleşir. Sistematik bir çalışma, kötü niyetli geliştiriciler, kullanıcılar veya dış saldırganların dahil olduğu, oluşturulmasından bakımına kadar MCP yaşam döngüsü boyunca 16 tehdit senaryosu belirlemiştir. Açığa çıkan sunucular başka bir risk oluşturmaktadır: Trend Micro, kimlik doğrulama veya şifreleme olmadan 492 çevrimiçi örnek bildirmiştir. Bu örnekler, doğal dil sorguları yoluyla bulut kaynakları gibi hassas verilere doğrudan okuma erişimi sağlamaktadır. Komut istemine enjeksiyon, komut enjeksiyonu ve eksik kimlik doğrulama — 25 en önemli güvenlik açığından 18'inde “kolay” olarak değerlendirilen kusurlar — yıllar önce web geliştirmede çözülen sorunları yansıtmaktadır, ancak cömert izinlere sahip AI ajanlarında hala devam etmektedir. Gerçek dünyadaki istismarlar arasında, saldırganlara e-postaları gizli kopya olarak gönderen ve kaldırılmadan önce 1.600 kez indirilen sahte bir npm paketi (“postmark-mcp”) ve uzaktan kod yürütmeyi mümkün kılan bir Figma MCP kusuru bulunmaktadır. Analizler, eklenti yığınlarında %92 istismar olasılığı olduğu konusunda uyarıda bulunarak, küçük zayıflıkları büyük ölçekli ihlallere dönüştürmektedir. Hızlı enjeksiyon, MCP'ye özgü değildir, ancak araçların güvenilmeyen girdilere maruz kalmasından kaynaklanır ve ajanlar arası (A2A) etkileşimlerde riskleri artırır.
| Güvenlik Açığı Türü | Açıklama | Sömürü Kolaylığı | Etki | Tartışmalardan Örnekler |
|--------------------|------------ -|--------------|--------|---------------------------|
| Araç Zehirlenmesi | Araç açıklamalarında gizlenmiş kötü amaçlı talimatlar | Kolay | Veri sızdırma, yetkisiz eylemler | MCP sunucuları üzerinden düşmanca saldırılar; SSH/API anahtarlarının sızdırılması |
| Açığa Çıkmış Sunucular | Kimlik doğrulaması yapılmamış çevrimiçi örnekler | Önemsiz | Hassas verilere arka kapı | 492 sunucu bulundu; %90'ı doğal dil erişimine izin veriyor |
| Komut/Emir Enjeksiyonu | Giriş doğrulamasını atlama | Kolay | Sistem güvenliğinin ihlali | İlk 25 rapor: 18/25 istismar edilebilir; yamalanmamış PHP ile paralellikler |
| Eksik Kimlik Doğrulama | Başlık/çerez desteği yok | Orta | Yetkisiz erişim | Uzaktan kurulumlar savunmasız; rug pull/çapraz kaynak sorunlarına yol açar |
| Eklenti Kötüye Kullanımı | Yığınlarda tehlikeye atılmış eklentiler | Yüksek (%92 olasılık) | Kurumsal çapta istismarlar | E-postaları çalan sahte npm paketleri; Figma uzaktan kod yürütme |
#### Yamalar, Düzeltmeler ve Azaltma Stratejileri
Tehditlere karşı alınan önlemler arasında Figma'nın güvenlik açığı düzeltmesi gibi belirli kusurlar için yamalar ve SlowMist gibi firmaların çoklu MCP ve kripto para senaryolarını kapsayan kapsamlı kontrol listeleri bulunmaktadır. Güvenlik tarayıcıları, Claude ve Cursor gibi araçları destekleyerek araç zehirlenmesi, rug pull (hash yoluyla) ve çapraz kaynak ihlallerini tespit eder. Vulnerablemcp[.]info gibi kaynaklar, daha iyi savunma için saldırı vektörlerini ayrıntılı olarak açıklar. En iyi uygulamalar, kötü amaçlı yazılım gibi sunucuları incelemeyi, kapsamları sınırlandırmayı, güvenilir sağlayıcıları kullanmayı ve güncellemelerden sonra MCP'leri yeniden onaylamayı vurgular. KQL sorguları, Microsoft Sentinel gibi ortamlarda maruz kalan sunucuları bulmaya yardımcı olur. Daha geniş savunma önlemleri arasında AI destekli güvenlik önlemleri, aşama özel korumalar ve sohbetlerdeki UI öğeleri için MCP-UI gibi standartlar bulunur.
#### Güncel Gelişmeler ve Entegrasyonlar
MCP'nin büyümesi, ChatGPT Geliştirici Modu, VS Code (GitHub MCP kayıt defteri ile v1.105) ve n8n iş akışları için TypingMind gibi platformlarda tam desteği içerir. DeMCP_AI'nin AI hesaplama için Web3 pazarı ve TaironAI'nin Oracle Katmanı gibi blok zinciri entegrasyonları, zincir üzerinde güvenlik ve modüler araçlar için MCP'yi kullanır. Otto MCP ve Briq'in Otonom İş Gücü Platformu gibi kurumsal araçlar, MCP'yi AI için “açık an” olarak konumlandırarak ajanların özerkliğini sağlar. Helidon 4.3.0 ve Hugging Face MCP Sunucusu gibi açık kaynak çabaları, yönetim API paritesi ve UI desteği gibi özellikler ekler. Katalizör önerileri, MCP aracılığıyla Cardano işlemlerini AI ile desteklemeyi amaçlamaktadır.
#### Topluluk Tartışmaları ve Analizleri
Analizler dengeli görüşleri vurgulamaktadır: MCP verimliliği artırır (örneğin, ajanlarda %97,3 araç çağırma güvenilirliği) ancak “pahalı dersler”den kaçınmak için disiplin gerektirir. Reddit ve Zenn.dev gibi platformlarda yapılan tartışmalar Japon bağlamındaki riskleri ele alırken, makaleler yükselen güvenlik manzaralarını incelemektedir. Topluluk, Jenova.ai'nin MCP'ye özel ajanı ve içerik yönetimi için Umbraco CMS MCP Beta gibi yeniliklere dikkat çekiyor. Tartışmalar arasında MCP'nin OpenAPI şemalarıyla uyumsuzluğu ve Story Protocol gibi entegrasyonlar yoluyla AI'nın sahip olduğu IP potansiyeli yer alıyor.
#### Resmi Duyurular ve Gelecekteki Yönelimler
Anthropic, OpenAI ve Google gibi kuruluşların duyuruları, MCP'nin AI arama alıntıları ve geliştirme araçlarındaki rolünü vurgulamaktadır. Devoxx gibi etkinliklerde MCP Java SDK ile ilgili uygulamalı oturumlar düzenlenmektedir. Gelecekteki beklentiler, AI API ağ geçitleri, ajanlar arası iletişim ve MCP-UI gibi standartların kullanılabilirliği artırırken eksiklikleri gidermesini öngörmektedir. Genel olarak, MCP'nin gidişatı yenilikçilik ile güvenlik gereklilikleri arasında bir denge kurarak, onu AI'nın bir sonraki aşaması için vazgeçilmez bir unsur haline getirmektedir.
**Önemli Alıntılar:**
- [Graham_dePenros, Araç Zehirleme Saldırıları hakkında](https://x.com/Graham_dePenros/status/1976216281033408741)
- [lbeurerkellner, Kritik Kusur Keşfi](https://x.com/lbeurerkellner/status/1907075048118059101)
- [jfrog, Sömürü Olasılığı hakkında](https://x.com/jfrog/status/1976719975881617553)
- [SlowMist_Team, Güvenlik Kontrol Listesi hakkında](https://x.com/SlowMist_Team/status/1911678320531607903)
- [rryssf_ En Önemli 25 Güvenlik Açığı](https://x.com/rryssf_/status/1970524674439422444)
- [LouisColumbus, Eklenti Riskleri hakkında](https://x.com/LouisColumbus/status/1976393986156941725)
- [rez0__, Güvenlik Açığı Kaynağı hakkında](https://x.com/rez0__/status/1922381770588053669)
- [liran_tal, Güvenlik Ortamı hakkında](https://x.com/liran_tal/status/1976362229294387584)
- [jiqizhixin, Sistematik Çalışma Güncellemesi](https://x.com/jiqizhixin/status/1976109107804270655)
- [0x534c, Açığa Çıkmış Sunucular hakkında](https://x.com/0x534c/status/1956999290863370481)
- [simonw, Hızlı Enjeksiyon Sorunları hakkında](https://x.com/simonw/status/1909955640107430226)
- [Chikor_Zi, Şema Sınırlamaları hakkında](https://x.com/Chikor_Zi/status/1939362725630562592)
- [TheHackersNews, Arka Kapı Olayı hakkında](https://x.com/TheHackersNews/status/1972581724992528746)
- [dsp_, Yeni Spesifikasyon hakkında](https://x.com/dsp_/status/1935740870680363328)
- [kakarot_ai, Korkunç Güvenlik Açıkları hakkında](https://x.com/kakarot_ai/status/1975599529681690820)
- [lbeurerkellner, Güvenlik Tarayıcısı hakkında](https://x.com/lbeurerkellner/status/1910379084758343827)
- [MCP_Community, Ürün Özeti hakkında](https://x.com/MCP_Community/status/1951369789685084254)
- [nutrientdocs, MCP Sunucularının Tedavisi hakkında](https://x.com/nutrientdocs/status/1976707785548030101)
- [GoogleCloudTech, Gemini CLI Entegrasyonu hakkında](https://x.com/GoogleCloudTech/status/1973493121250902040)
- [rootstock_io, Rootstock MCP Sunucusu hakkında](https://x.com/rootstock_io/status/1975656743799902686)
- [nowitnesslabs, Catalyst Önerisi hakkında](https://x.com/nowitnesslabs/status/1972563255479459990)
- [BriqHQ, OTTO MCP Duyurusu hakkında](https://x.com/BriqHQ/status/1972723699016183888)
- [evalstate, HF MCP Sunucusu hakkında](https://x.com/evalstate/status/1975188323124519293)
- [100xDarren, TAIRO Güncellemesi hakkında](https://x.com/100xDarren/status/1973515775593029886)
- [KrekhovetsRZ, Story Protocol Entegrasyonu hakkında](https://x.com/KrekhovetsRZ/status/1975278135961702515)
- [helidon_project, Helidon 4.3.0 Sürümü hakkında](https://x.com/helidon_project/status/1973727994742239401)
- [ChromiumDev, DevTools MCP hakkında](https://x.com/ChromiumDev/status/1976422660880875687)
- [christzolov, Devoxx Talk hakkında](https://x.com/christzolov/status/1976209066423947619)
- [Bedrock AgentCore'da awsdevelopers](https://x.com/awsdevelopers/status/1974900254349603273)
- [lilyraynyc, AI Search Citations hakkında](https://x.com/lilyraynyc/status/1973044734206628353)
- [HexawareGlobal, MuleSoft Desteği hakkında](https://x.com/HexawareGlobal/status/1975546653667963028)
- [umbraco, CMS MCP Beta hakkında](https://x.com/umbraco/status/1975463678733414582)
- [VS Code Sürümünde code](https://x.com/code/status/1976332459886182627)
- [n8n Entegrasyonunda TypingMindApp](https://x.com/TypingMindApp/status/1973767427872772513)

### AI Ajanları Güvenlik Protokolleri

Araştırmalar, AI ajanlarının (otonom görevleri yerine getiren AI sistemleri) güvenlik risklerinin yüksek olduğunu gösteriyor; prompt enjeksiyonu, veri sızıntısı ve kötüye kullanım gibi tehditler yaygın. Ancak, katmanlı savunmalar ve en iyi uygulamalarla bu riskler yönetilebilir. 

- **Temel Riskler**: AI ajanları, LLM'lerin (büyük dil modelleri) açıklıklarından etkilenerek veri zehirlenmesi, jailbreak ve araç zehirlenmesi gibi saldırılara maruz kalır; bu, gizlilik ve bütünlük ihlallerine yol açabilir.
- **Ana Savunmalar**: En az yetki ilkesi, giriş/çıkış doğrulaması ve sandboxing gibi geleneksel yöntemler, AI'ye özgü guard modelleri ve davranış sertifikaları ile birleştirilerek etkili koruma sağlar.
- **Potansiyel Tartışmalar**: Bazı uzmanlar, AI ajanlarının tam özerkliğinin riskleri artırdığını savunurken, diğerleri katı protokollerle dengelenebileceğini belirtiyor; ancak, standartlaşma eksikliği genel bir endişe kaynağı.

#### Giriş Doğrulaması ve Sandboxing
Girişlerin sıkı doğrulanması (örneğin, JSON formatı ve regex filtreleri) ve ajanların izole ortamlarda (sandbox) çalıştırılması, prompt enjeksiyonu gibi saldırıları önler. Bu, ajanların yalnızca gerekli kaynaklara erişmesini sağlar.

#### Şifreleme ve İzleme
Tüm verilerin uçtan uca şifrelenmesi (TLS 1.3, AES-256) ve davranış izlemesi (OpenTelemetry gibi araçlarla), anormallikleri erken tespit eder. Rate limiting, DoS saldırılarını sınırlayarak ajanların kullanılabilirliğini korur.

#### Protokol Spesifik Yaklaşımlar
A2AS gibi çerçeveler, davranış sertifikaları ve bağlam bütünlüğü ile ajan-ajan iletişimini güvence altına alır. MCP (Model Context Protocol) için araç zehirlenmesi tarayıcıları önerilir.

---

AI ajanları, büyük dil modelleri (LLM'ler) üzerine kurulu otonom sistemler olarak, çeşitli güvenlik tehditleriyle karşı karşıya kalır. Bu tehditler, geleneksel yazılım güvenlik sorunlarından farklı olarak, ajanların karar alma ve eylem yürütme yeteneklerinden kaynaklanır. Araştırmalar, ajanların gizlilik, bütünlük ve kullanılabilirlik açısından risk taşıdığını vurgular; örneğin, prompt enjeksiyonu yoluyla zararlı eylemler tetiklenebilir veya veri sızıntıları meydana gelebilir. Bu kapsamlı inceleme, son bir yıldaki web ve X (eski Twitter) kaynaklarından derlenen bilgileri temel alır, tehdit modellerini, saldırı vektörlerini ve savunma stratejilerini detaylandırır. Geleneksel ve AI'ye özgü yöntemler bir araya getirilerek katmanlı bir yaklaşım önerilir.

#### Tehdit Modelleri ve Saldırı Vektörleri
AI ajanlarının tehdit modeli, metin tabanlı giriş/çıkışa dayanır; güvenli bir sunucuda barındırılırken, kullanıcı erişimi API ile sınırlıdır. Ancak, LLM'lerin ürettiği eylemler, sistem açıklıklarını istismar edebilir. Ana vektörler şöyle:

1. **Oturum Yönetimi Açıkları**: Çok kullanıcılı ajanlarda oturum izolasyonu eksikliği, bilgi sızıntısına (gizlilik ihlali) veya yanlış eylem atamasına (bütünlük ihlali) yol açar. Kaynak yoğun sorgularla DoS saldırıları mümkün olur.
2. **Model Kirlenmesi ve Gizlilik Sızıntıları**: Kullanıcı sohbet geçmişleriyle ince ayarlanmış modeller, veri zehirlenmesine açıktır. Hassas veriler (SSN, hesap numaraları) LLM'lerde saklanarak çıkarılabilir; örnek olarak Samsung'un ChatGPT yasağı verilebilir.
3. **Ajan Programı Açıkları**:
   - **Sıfır Atış Eylemleri**: Halüsinasyonlar veya jailbreak'ler, istenmeyen komutlar üretir; araç belgelerine gömülü prompt'lar veri sızıntısına neden olur.
   - **Bilişsel Planlama**: ReAct veya Tree-of-Thoughts gibi yöntemler, her adımda yan etkiler yaratır; kaynak tüketimiyle kullanılabilirlik etkilenir.
   Deneyler (BashAgent ile 95 güvenlik görevi), kısıtsız ortamlarda %96 gizlilik, %85.7 bütünlük ve %62.9 kullanılabilirlik saldırılarının başarılı olduğunu gösterir.

X tartışmalarında, araç zehirlenmesi (tool poisoning) ve plan enjeksiyonu gibi yeni saldırılar öne çıkar; örneğin, ajan hafızasına gizli talimatlar eklenerek kalıcı zarar verilebilir.

Türkçe kaynaklarda, MCP (Model Context Protocol) gibi protokollerde araç zehirlenmesi ve ajan-ajan (A2A) iletişim riskleri vurgulanır; kötü niyetli sunucular, gizli talimatlarla veri dışa aktarımı sağlar.

#### Savunma Stratejileri
Savunmalar, bileşen düzeyinde odaklanır; izolasyon, şifreleme ve resmi modelleme ile uygulanır.

1. **Oturum Yönetimi**: Benzersiz oturum kimlikleri ve KVDB ile tarihçeyi izole edin; durum dönüştürücü monadlar (state transformer monads) ile doğrulanabilir hesaplamalar sağlayın.
2. **Model Koruması**:
   - **Oturumsuz Modeller**: Özel verileri filtreleyin; FPETS (Format-Preserving Encryption for Text Slicing) ile şifreleme, başarı oranlarını %38-89 korur. FHE (Fully Homomorphic Encryption) hesaplamalara izin verir.
   - **Oturum Farkındalığı**: Prompt tuning ile kullanıcıya özgü parametreler ekleyin, temel LLM'yi dondurun.
3. **Sandboxing**: Kaynak sınırlamaları ve Docker gibi izole ortamlar; kısıtlı BashAgent, tüm saldırıları engeller. Beyaz/siyah listeler ve rate limiting, uzak erişimi korur.

Jit.io'nun 7 ipucu:
- Giriş doğrulama ve çıkış sanitizasyonu (Rebuff gibi araçlarla).
- Yetki kısıtlaması ve izolasyon (en az yetki ilkesi).
- Kod ve bağımlılık taraması (Semgrep, Jit ajanları).
- Uçtan uca şifreleme (TLS 1.3, AES-256).
- Davranış izleme ve rate limiting (OpenTelemetry).
- Just-in-Time güvenlik (dinamik erişim).
- Gerçek zamanlı yanıt ve kurtarma (SIEM entegrasyonu).

Google Cloud'un katmanlı yaklaşımı: Kimlik doğrulama, yetkilendirme, denetlenebilirlik ve güvenli geliştirme ile geleneksel; guard modelleri ve advers訓練 ile AI'ye özgü.

A2AS Çerçevesi: BASIC modeli (Behavior Certificates, Authenticated Prompts, Security Boundaries, In-Context Defenses, Codified Policies) ile ajan güvenliğini sağlar; bağlam penceresinde çalışır, prompt enjeksiyonunu önler.

OWASP Tabanlı Kontrol Listesi: 15 kategoride 163 öğe; AI yönetişimi, güvenli tasarım, prompt güvenliği, ajan aracı güvenliği gibi alanlar kapsar.

#### En İyi Uygulamalar ve Çerçeveler
- **Guard Modelleri**: Yüksek etkili eylemleri denetler.
- **Advers Eğitim**: Simüle saldırılarla dayanıklılık artırılır.
- **SLSA Çerçevesi**: Yazılım tedarik zinciri güvenliği için SBOM ile kullanılır.
- **A2A Protokolü**: Ajanlar arası iletişimde sandboxing ve giriş sanitizasyonu.
- **MCP Güvenliği**: Araç zehirlenmesi tarayıcıları ve checklist'ler.

Türkçe bağlamda, IBM Güvenlik Doğrulama AI Ajanı gibi entegrasyonlar, otomasyon ve zeki karar alma için vurgulanır; yapay zeka siber güvenlik teknolojilerini şekillendirirken, log toplama ve regex gibi protokoller entegre edilir.

#### Risk ve Savunma Tablosu

| Tehdit Türü | Açıklama | Savunma Stratejisi | Kaynak |
|-------------|----------|---------------------|--------|
| Prompt Enjeksiyonu | Zararlı girişlerle ajan manipülasyonu | Giriş sanitizasyonu, guard modelleri | , , [post:28] |
| Veri Zehirlenmesi | Eğitim verilerine müdahale | Veri bütünlüğü doğrulaması, diferansiyel gizlilik | ,  |
| Araç Zehirlenmesi | Araç tanımlarında gizli talimatlar | Tarayıcılar ve beyaz listeler | [post:18],  |
| DoS Saldırıları | Kaynak tüketimi | Rate limiting, kaynak sınırlamaları | ,  |
| Gizlilik Sızıntıları | Hassas veri ifşası | Şifreleme (FPETS, FHE) | ,  |
| Ajan-Ajan Enfeksiyonu | Çok ajanlı sistemlerde bulaşma | A2AS gibi protokoller | , [post:22] |

#### Gelecek Yönelimler
AI ajan güvenliği, standartlaşma (A2AS gibi) ve blockchain entegrasyonuyla evrilir; örneğin, Theoriq protokolü katkı kanıtı ve ceza mekanizmalarıyla güven sağlar. Çok ajanlı sistemlerde (multi-agent AI), dağıtılmış yapı güvenlik artırır. Ancak, token kullanım yükü ve model sapmaları gibi sınırlamalar devam eder.

Bu inceleme, AI ajanlarının dengeli kullanımını teşvik eder; riskler yönetilebilir olsa da, sürekli izleme ve güncelleme şarttır.

**Ana Kaynaklar:**
- [Security of AI Agents - arXiv](https://arxiv.org/pdf/2406.08689.pdf)
- [7 Proven Tips to Secure AI Agents - Jit.io](https://www.jit.io/resources/devsecops/7-proven-tips-to-secure-ai-agents-from-cyber-attacks)
- [AI Agent Security - Google Cloud](https://cloud.google.com/transform/ai-agent-security-how-to-protect-digital-sidekicks-and-your-business)
- [A2AS Framework PDF](https://hmdhiqqomsdmtwjq.public.blob.vercel-storage.com/a2as-framework-1.0.pdf)
- [AI Security Checklist - OWASP](https://shivang0.github.io/index.html)
- [AI Agent Security: MCP Security - Medium](https://alican-kiraz1.medium.com/ai-agent-security-mcp-security-0516cb41e800)
- [SynthaMan on A2AS Framework](https://x.com/SNXified/status/1975304303398035528)
- [AISecHub on Agentic AI Runtime Security](https://x.com/AISecHub/status/1975932208985637126)
- [Vercel on Prompt Injection](https://x.com/vercel/status/1932115736841068681)
- [Het Mehta on AI Security Checklist](https://x.com/hetmehtaa/status/1953901455523635208)