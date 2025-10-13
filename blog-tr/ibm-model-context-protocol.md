# Model Context Protocol (MCP): AI için Yeni Bir Standart

**Yazar:** Anna Gutowska – AI Engineer, Developer Advocate, IBM  
**Kaynak:** [IBM Think Blog](https://www.ibm.com/think/topics/model-context-protocol)[1](https://www.ibm.com/think/topics/model-context-protocol)

## MCP Nedir?

**Model Context Protocol (MCP)**, yapay zekâ uygulamalarının dış servislerle (araçlar, veritabanları, şablonlar vb.) etkili şekilde iletişim kurmasını sağlayan bir standartlaştırma katmanıdır. MCP, özellikle çoklu ajan sistemlerinde bilgi yayılımını kolaylaştırır ve araç entegrasyon hatalarını azaltır.

## MCP'nin Amacı

MCP, AI ajanlarının bağlam farkındalığı kazanmasını ve standart bir protokol üzerinden araçlarla etkileşim kurmasını sağlar. Bu, tıpkı USB-C'nin donanım dünyasında sunduğu evrensel bağlantı gibi, AI dünyasında araçlarla “tak-çalıştır” entegrasyonu sağlar.

## LLM'ler ve Araçlar

Büyük dil modelleri (LLM'ler) kendi başlarına sınırlı yeteneklere sahiptir:

- Metin tamamlama
- Temel soru-cevap
- Duygu analizi
- Dil çevirisi

Ancak gerçek zamanlı bilgiye erişim veya eylem gerçekleştirme gibi görevler için dış araçlara ihtiyaç duyarlar. MCP, bu araçların entegrasyonunu standartlaştırarak LLM'lerin daha anlamlı ve bağlamsal sonuçlar üretmesini sağlar.

## MCP Mimarisi

MCP üç ana bileşenden oluşur:

- **MCP Host:** Kullanıcı isteklerini alan ve bağlam erişimi sağlayan AI uygulaması (örneğin Claude Desktop).
- **MCP Client:** Host ile Server arasında iletişimi yöneten, istekleri yapılandıran ve yanıtları işleyen bileşen.
- **MCP Server:** Dış servislerle bağlantı kurarak LLM'e bağlam sağlayan sunucu (örneğin Slack, GitHub, Docker).

## MCP Sunucuları Üzerinden Sağlananlar

- **Resources:** Veri tabanlarından bilgi çekme (salt veri, işlem yok).
- **Tools:** API çağrıları veya hesaplamalar gibi eylem gerçekleştiren araçlar.
- **Prompts:** LLM ile sunucu arasındaki iletişim için yeniden kullanılabilir şablonlar.

## Veri Aktarımı

MCP, istemci-sunucu arasında **JSON-RPC 2.0** formatında veri iletir:

- **Stdio:** Yerel kaynaklar için senkron veri aktarımı.
- **SSE (Server-Sent Events):** Uzak kaynaklar için asenkron veri aktarımı.

## MCP'nin Faydaları

- Araç entegrasyonunu kolaylaştırır.
- Geliştirici yükünü azaltır.
- Otomasyon altyapısını daha dayanıklı hale getirir.
- RAG (Retrieval-Augmented Generation) gibi sistemleri destekler.

## Gelecek Vizyonu

MCP, AI ajanlarının gerçek dünya ortamlarına dinamik şekilde uyum sağlamasını kolaylaştıran bir standarttır. Bu sayede insan müdahalesi azalır, karmaşık iş akışları otomatikleşir ve insanlar daha yaratıcı görevlere odaklanabilir.