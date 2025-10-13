# MCP AraÅŸtÄ±rma Raporu

## Ã–zet
- MCP (Model Context Protocol) mimarisi, istemciâ€“sunucu ayrÄ±mÄ± ve JSONâ€‘RPC tabanlÄ± araÃ§/ kaynak keÅŸfi ile birlikte Ã§alÄ±ÅŸabilirliÄŸi artÄ±rÄ±r.
- KullanÄ±m alanlarÄ±; asistan entegrasyonu, otomasyon (tasarÄ±mdan koda), kurumsal veri eriÅŸimi ve cihaz kontrolÃ¼nÃ¼ kapsar.
- GÃ¼venlikte temel riskler: araÃ§ zehirleme, prompt enjeksiyonu, aÃ§Ä±k sunucular, tedarik zinciri ve RCE vakalarÄ±; savunmada sandboxing, en az yetki ve denetlenebilirlik Ã¶ne Ã§Ä±kar.
- StandartlaÅŸma ve yÃ¶netiÅŸim eksikleri ile performans/maliyet konularÄ±, gelecek Ã§alÄ±ÅŸmalarÄ±n odaÄŸÄ±dÄ±r.

Not: AyrÄ±ntÄ±lar iÃ§in Rapor bÃ¶lÃ¼mÃ¼ne geÃ§iniz.

## Ä°Ã§indekiler
- [Ã–zet](#Ã¶zet)
- [Rapor](#rapor)
- [Ek A: LiteratÃ¼r](#ek-a-literatÃ¼r)
- [Ek B: Google Scholar ve Sentez](#ek-b-google-scholar-ve-sentez)
- [Ek C: GÃ¼ncel Olaylar](#ek-c-gÃ¼ncel-olaylar)

## Rapor

### GiriÅŸ

**Model Context Protocol (MCP)**, Anthropic ÅŸirketi tarafÄ±ndan aÃ§Ä±k kaynak olarak geliÅŸtirilmiÅŸ bir protokoldÃ¼r ve bÃ¼yÃ¼k dil modellerini (Large Language Models - *LLM*) harici veri kaynaklarÄ± ve araÃ§larla entegre etmeyi amaÃ§lar. Bir bakÄ±ma, yapay zeka uygulamalarÄ± iÃ§in **USB-C standardÄ±** gibi Ã§alÄ±ÅŸarak LLM tabanlÄ± uygulamalarÄ±n dÄ±ÅŸ sistemlerle baÄŸlanmasÄ± iÃ§in standart bir yol saÄŸlar. Bu araÅŸtÄ±rmanÄ±n amacÄ±, MCP protokolÃ¼nÃ¼n teknik mimarisi ile aÄŸ iÃ§i iÅŸleyiÅŸ modelini inceleyerek yazÄ±lÄ±m geliÅŸtirme sÃ¼reÃ§lerindeki kullanÄ±m biÃ§imlerini ortaya koymak ve protokolÃ¼n siber gÃ¼venlik baÄŸlamÄ±nda oluÅŸturabileceÄŸi potansiyel riskleri deÄŸerlendirmektir. Bu doÄŸrultuda, MCPâ€™nin temel hedefleri ve kullanÄ±m alanlarÄ±, mimari yapÄ±sÄ± ve veri iletim mekanizmasÄ±, hangi katmanda Ã§alÄ±ÅŸtÄ±ÄŸÄ± ve bunun saÄŸladÄ±ÄŸÄ± avantajlar ile protokolÃ¼n aÃ§Ä±k kaynak olmasÄ±nÄ±n gÃ¼venliÄŸe etkileri ele alÄ±nacaktÄ±r. AyrÄ±ca MCPâ€™ye yÃ¶nelik olasÄ± saldÄ±rÄ± tÃ¼rleri (Ã¶rn. Ortadaki Adam, Replay, Enjeksiyon) incelenerek Anthropicâ€™in (Antopic) uyguladÄ±ÄŸÄ± gÃ¼venlik Ã¶nlemlerinin yeterliliÄŸi deÄŸerlendirilecek ve **MCPâ€™nin gÃ¼venli bir ÅŸekilde uygulanabilmesi iÃ§in Ã¶neriler** sunulacaktÄ±r.

<img width="1207" height="799" alt="resim" src="https://github.com/user-attachments/assets/bdf1510b-66f6-427b-9562-f8653e73d66e" />


### MCP ProtokolÃ¼nÃ¼n AmacÄ± ve KullanÄ±m AlanlarÄ±

MCP protokolÃ¼nÃ¼n temel amacÄ±, LLM tabanlÄ± yapay zeka uygulamalarÄ± ile harici araÃ§lar, veri kaynaklarÄ± ve hizmetler arasÄ±nda **standart bir baÄŸlamsal iletiÅŸim** saÄŸlamaktÄ±r. Bu sayede bir yapay zeka modeli, kÄ±sÄ±tlÄ± kendi bilgi havuzunun Ã¶tesine geÃ§erek gÃ¼ncel verilere eriÅŸebilir, Ã§eÅŸitli eylemleri tetikleyebilir veya harici uygulamalardan sonuÃ§lar alabilir. Ã–rneÄŸin GitHub Copilot gibi bir kod yardÄ±mÄ± aracÄ±, MCP Ã¼zerinden GitHubâ€™Ä±n kendi hizmetleriyle veya Ã¼Ã§Ã¼ncÃ¼ parti araÃ§larla entegre olarak daha ileri iÅŸlemler yapabilmektedir. Anthropicâ€™in Claude modeli gibi bir LLM de MCP sayesinde harici â€œaraÃ§larâ€ kullanarak ide ortamÄ±nda dosya sistemine eriÅŸmek veya bir hata izleme (sentry) platformundan veri Ã§ekmek gibi eylemlere giriÅŸebilir.

<img width="960" height="540" alt="resim" src="https://github.com/user-attachments/assets/ac7686e8-9c5d-4a30-be7c-9fa1f7328325" />

MCP protokolÃ¼, geniÅŸ bir yelpazedeki kullanÄ±m senaryolarÄ±nÄ± mÃ¼mkÃ¼n kÄ±larak yapay zekÃ¢ uygulamalarÄ±nÄ±n yeteneklerini artÄ±rÄ±r. AÅŸaÄŸÄ±da MCPâ€™nin saÄŸlayabildiÄŸi bazÄ± olanaklar listelenmiÅŸtir:

* **KiÅŸisel Asistan Entegrasyonu:** Yapay zekÃ¢ â€œagentâ€larÄ± kullanÄ±cÄ±larÄ±n Google Takvimi veya Notion hesaplarÄ±na baÄŸlanarak daha kiÅŸiselleÅŸtirilmiÅŸ asistanlar gibi davranabilir. Ã–rneÄŸin, takvimden randevularÄ± okuma veya yeni notlar oluÅŸturma gibi iÅŸlemleri gerÃ§ekleÅŸtirebilir.
* **TasarÄ±m'dan Koda Otomasyon:** Claude Code gibi bir AI aracÄ±, MCP aracÄ±lÄ±ÄŸÄ±yla bir Figma tasarÄ±mÄ±nÄ± analiz ederek komple bir web uygulamasÄ±nÄ± otomatik olarak oluÅŸturabilir. Bu, tasarÄ±m ve geliÅŸtirme sÃ¼reÃ§lerini hÄ±zlandÄ±ran bir entegrasyon Ã¶rneÄŸidir.
* **Kurumsal Veri EriÅŸimi:** Kurum iÃ§indeki bir sohbet botu, MCP Ã¼zerinden organizasyonun farklÄ± veritabanlarÄ±na aynÄ± anda baÄŸlanabilir ve kullanÄ±cÄ±nÄ±n doÄŸal dilde sorduÄŸu sorulara dayanarak gerÃ§ek zamanlÄ± veri analizi yapabilir. Bu sayede tek bir arayÃ¼z Ã¼zerinden birden Ã§ok veri kaynaÄŸÄ± taranabilir.
* **Fiziksel Cihaz KontrolÃ¼:** Bir yapay zekÃ¢ modeli, MCP ile Blender gibi bir 3D tasarÄ±m aracÄ±na ve bir 3B yazÄ±cÄ±ya baÄŸlanarak, doÄŸal dil komutlarla 3D model tasarlayÄ±p bunu yazÄ±cÄ±dan basabilir.

YukarÄ±daki Ã¶rnekler MCPâ€™nin **genel amaÃ§lÄ± bir entegrasyon altyapÄ±sÄ±** olarak ne denli esnek kullanÄ±labildiÄŸini gÃ¶stermektedir. Son kullanÄ±cÄ± aÃ§Ä±sÄ±ndan bu, yapay zekÃ¢ destekli uygulamalarÄ±n kendi verilerine eriÅŸip gerekirse kullanÄ±cÄ± adÄ±na eyleme geÃ§ebilen daha yetenekli asistanlar haline gelmesi demektir. GeliÅŸtiriciler iÃ§in ise MCP, bir yapay zekÃ¢ uygulamasÄ±na entegrasyon noktalarÄ± eklerken zaman kazandÄ±ran ve karmaÅŸÄ±klÄ±ÄŸÄ± azaltan standart bir arayÃ¼z sunmaktadÄ±r.

### MCP'nin Mimari YapÄ±sÄ± ve Veri Ä°letim MekanizmasÄ±


<img width="840" height="328" alt="resim" src="https://github.com/user-attachments/assets/ba600697-942e-426f-ad1c-839875ef9772" />


MCP istemci ve sunucularÄ±nÄ±n LLM ile etkileÅŸimini gÃ¶steren Ã¶rnek bir akÄ±ÅŸ diagramÄ±. KullanÄ±cÄ± isteÄŸi, istemci tarafÄ±ndan LLM'ye iletilir; LLM uygun aracÄ± seÃ§erek sunucuya Ã§aÄŸrÄ± yapar ve sonuÃ§ yine LLM Ã¼zerinden kullanÄ±cÄ±ya dÃ¶ner.*

MCP protokolÃ¼, istemci-sunucu modeline dayalÄ± **iki katmanlÄ± bir mimariye** sahiptir. Katmanlardan ilki **veri katmanÄ±** (*data layer*) olup istemci ile sunucu arasÄ±ndaki mesajlarÄ±n yapÄ±sÄ±nÄ± ve anlamÄ±nÄ± tanÄ±mlayan bir JSON-RPC 2.0 tabanlÄ± protokoldÃ¼r. Bu katmanda baÄŸlantÄ±nÄ±n baÅŸlatÄ±lmasÄ±, sÃ¼rdÃ¼rÃ¼lmesi ve sonlandÄ±rÄ±lmasÄ± gibi yaÅŸam dÃ¶ngÃ¼sÃ¼ yÃ¶netimi; sunucunun saÄŸlayabileceÄŸi *araÃ§lar* (tools) ve *kaynaklar* (resources) gibi iÅŸlevler; istemcinin LLM'den Ã§Ä±ktÄ± Ã¼retmesini talep etme veya kullanÄ±cÄ± girdisi isteme gibi kabiliyetler ve uyarÄ±/iletiÅŸim amaÃ§lÄ± *bildirimler* yer alÄ±r. Ä°kinci katman olan **taÅŸÄ±ma katmanÄ±** (*transport layer*), veri alÄ±ÅŸveriÅŸinin hangi iletiÅŸim kanallarÄ± Ã¼zerinden ve nasÄ±l yapÄ±lacaÄŸÄ±nÄ± tanÄ±mlar; baÄŸlantÄ± kurulumu, mesaj Ã§erÃ§eveleri ve taraflar arasÄ±nda kimlik doÄŸrulama bu katmanda ele alÄ±nÄ±r. MCPâ€™nin tasarÄ±mÄ±nda mevcut iki taÅŸÄ±ma yÃ¶ntemi ÅŸunlardÄ±r:

* **STDIO TaÅŸÄ±masÄ±:** Ä°stemci ve sunucunun aynÄ± makinede yerel olarak Ã§alÄ±ÅŸtÄ±ÄŸÄ± durumlarda standart girdi/Ã§Ä±ktÄ± akÄ±ÅŸÄ± Ã¼zerinden iletiÅŸim kurulabilir. Bu yÃ¶ntem, herhangi bir aÄŸ protokolÃ¼ kullanmadÄ±ÄŸÄ± iÃ§in ek gecikme veya aÄŸ trafiÄŸi oluÅŸturmaz; dolayÄ±sÄ±yla maksimum performans saÄŸlar ve Ã¶zellikle bir IDE iÃ§inde Ã§alÄ±ÅŸtÄ±rÄ±lan yerel araÃ§lar iÃ§in idealdir.
* **AkÄ±ÅŸ Destekli HTTP TaÅŸÄ±masÄ±:** Ä°stemci ile sunucu arasÄ±nda HTTP Ã¼zerinden iletiÅŸim kurulmasÄ±nÄ± saÄŸlar. Ä°stemci, sunucuya JSON tabanlÄ± isteklerini HTTP POST ile gÃ¶nderirken; sunucu gerektiÄŸinde **Server-Sent Events (SSE)** kullanarak istemciye akan (*streaming*) yanÄ±tlar iletebilir. Bu yÃ¶ntem uzaktaki (bulut veya internet Ã¼zerindeki) MCP sunucularÄ±na baÄŸlanmak iÃ§in kullanÄ±lÄ±r ve standart HTTP kimlik doÄŸrulama mekanizmalarÄ±nÄ± destekler (taÅŸÄ±yÄ±cÄ± jetonlar, API anahtarlarÄ± veya Ã¶zel baÅŸlÄ±klar gibi). Uzaktan iletiÅŸimde verinin gizliliÄŸi ve bÃ¼tÃ¼nlÃ¼ÄŸÃ¼ iÃ§in MCP Ã¼zerinden **HTTPS (TLS ÅŸifrelemesi)** kullanÄ±lmasÄ± Ã¶nerilmektedir.

YukarÄ±daki mimari sayesinde MCP, birden fazla sunucuya aynÄ± anda baÄŸlanabilen esnek bir istemci-Ã§oklu sunucu topolojisi oluÅŸturur. Bu yapÄ±da **MCP Ä°stemcisi**, LLM barÄ±ndÄ±ran uygulamanÄ±n iÃ§inde Ã§alÄ±ÅŸarak her bir MCP sunucusuyla birebir baÄŸlantÄ± kuran bileÅŸendir. **MCP Sunucusu** ise harici baÄŸlam bilgisini saÄŸlayan baÄŸÄ±msÄ±z bir sÃ¼reÃ§tir; dosya sistemi, veritabanÄ±, harici API gibi kaynaklara eriÅŸebilir ve bunlarÄ± istemciye bir â€œaraÃ§â€ arayÃ¼zÃ¼yle sunar. Ã–rneÄŸin Visual Studio Code editÃ¶rÃ¼ bir MCP **host** uygulamasÄ± olarak dÃ¼ÅŸÃ¼nÃ¼lebilir; VS Code, Sentry hata izleme sistemi iÃ§in bir MCP sunucusuna baÄŸlandÄ±ÄŸÄ±nda (uzak bir sunucu), aynÄ± anda yerel dosya sistemi eriÅŸimi sunan baÅŸka bir MCP sunucusuna da baÄŸlanabilir. Bu durumda VS Code iÃ§inde her sunucu baÄŸlantÄ±sÄ± iÃ§in ayrÄ± bir MCP istemci nesnesi Ã§alÄ±ÅŸÄ±r ve her biri ilgili sunucusundan veri Ã§eker.

<img width="836" height="512" alt="resim" src="https://github.com/user-attachments/assets/d0cdaa6e-aff0-4d03-ab74-bbd6107c5ff1" />

**Veri iletim mekanizmasÄ±**, istemci, sunucu ve LLM arasÄ±ndaki etkileÅŸimle gerÃ§ekleÅŸir. Bu akÄ±ÅŸÄ± adÄ±m adÄ±m incelemek gerekirse:

1. **KullanÄ±cÄ± isteÄŸi:** Son kullanÄ±cÄ±, MCP entegrasyonuna sahip AI uygulamasÄ±ndan (Ã¶rneÄŸin bir sohbet arayÃ¼zÃ¼ veya IDE) bir talepte bulunur. Bu talep doÄŸal dilde bir komut, soru veya gÃ¶rev tanÄ±mÄ± olabilir ve Ã¶ncelikle **MCP istemcisi** tarafÄ±ndan ele alÄ±nÄ±r.
2. **LLM ile planlama:** MCP istemcisi, baÄŸlÄ± olduÄŸu MCP sunucularÄ±nÄ±n hangi araÃ§larÄ± saÄŸladÄ±ÄŸÄ± bilgisini elinde tutar. KullanÄ±cÄ±nÄ±n isteÄŸini alÄ±r almaz istemci, sunuculardan aldÄ±ÄŸÄ± bu yetenek bilgilerini de **LLMâ€™ye aktarÄ±r**. BaÅŸka bir deyiÅŸle, LLMâ€™ye *â€œÅŸu ÅŸu araÃ§lar mevcutâ€* bilgisini vererek kullanÄ±cÄ± talebini Ã§Ã¶zÃ¼mler. LLM, verilen gÃ¶revi yerine getirmek iÃ§in hangi araca ihtiyaÃ§ olduÄŸunu ve bu araca hangi parametrelerle Ã§aÄŸrÄ± yapÄ±lacaÄŸÄ±nÄ± kararlaÅŸtÄ±rÄ±r ve istemciye bir yanÄ±t Ã¼retir.
3. **Sunucuya istek:** LLMâ€™nin yanÄ±tÄ±na gÃ¶re MCP istemcisi, ilgili aracÄ± barÄ±ndÄ±ran MCP **sunucusuna** bir istek gÃ¶nderir. Bu istek, belirli bir aracÄ± Ã§alÄ±ÅŸtÄ±rma komutunu ve gerekli parametreleri iÃ§erir. Ä°letiÅŸim, yerel sunucu ise STDIO Ã¼zerinden, uzak sunucu ise HTTP istekleri ile gerÃ§ekleÅŸir.
4. **Sunucu iÅŸlemi ve yanÄ±t:** MCP sunucusu, kendisine iletilen komutu gerÃ§ekleÅŸtirir. Ã–rneÄŸin bir dosya okuma aracÄ±na parametre olarak bir dosya yolu verildiyse, sunucu dosyayÄ± okuyup iÃ§eriÄŸini dÃ¶ndÃ¼rÃ¼r. Sunucu, iÅŸlemin sonucunu (ya da hata Ã§Ä±ktÄ±ysa hata bilgisini) MCP istemcisine geri gÃ¶nderir.
5. **LLM'nin sonuÃ§ Ã¼retmesi:** MCP istemcisi sunucudan aldÄ±ÄŸÄ± ham sonucu tekrar LLMâ€™ye iletir (veya LLM zaten Ã¶nceki adÄ±mda bu sonucu bekliyor olabilir). LLM, sunucudan gelen veriyi kullanarak kullanÄ±cÄ±ya verilecek nihai cevabÄ± oluÅŸturur. Ã–rneÄŸin, dosya iÃ§eriÄŸi istenmiÅŸse bunu kullanÄ±cÄ±ya uygun biÃ§imde sunan bir metin cevabÄ± Ã¼retir.
6. **KullanÄ±cÄ±ya sunum:** Son olarak MCP istemcisi, LLMâ€™nin Ã¼rettiÄŸi cevabÄ± alÄ±r ve uygulama arayÃ¼zÃ¼ Ã¼zerinden kullanÄ±cÄ±ya gÃ¶sterir. KullanÄ±cÄ±, talebinin sonucunu insan tarafÄ±ndan yazÄ±lmÄ±ÅŸÃ§asÄ±na doÄŸal bir dilde almÄ±ÅŸ olur.

Bu iÅŸlem dÃ¶ngÃ¼sÃ¼, MCP sayesinde LLM tabanlÄ± bir sistemin **etkin bir araÃ§ kullanÄ±cÄ±sÄ±na** dÃ¶nÃ¼ÅŸmesini saÄŸlamaktadÄ±r. Ã–nemle vurgulanmalÄ±dÄ±r ki MCP, LLM ile araÃ§lar arasÄ±nda doÄŸrudan bir baÄŸlantÄ± kurmaz; bunun yerine istemci ve sunucu aracÄ±lÄ±ÄŸÄ±yla kontrollÃ¼ bir entegrasyon gerÃ§ekleÅŸtirir. Ä°stemci tarafÄ± LLM ile konuÅŸmaktan sorumlu iken, sunucu tarafÄ± gerÃ§ek dÃ¼nya araÃ§larÄ±nÄ± Ã§alÄ±ÅŸtÄ±rma gÃ¶revini Ã¼stlenir. Bu ayrÄ±m, gÃ¼venlik ve kontrol aÃ§Ä±sÄ±ndan da Ã¶nemlidir Ã§Ã¼nkÃ¼ LLMâ€™nin her ÅŸeye doÄŸrudan eriÅŸimi olmaz; sadece istemcinin sunduÄŸu arayÃ¼z dahilinde eylem yapabilir.

### ProtokolÃ¼n Katman Seviyesi ve AvantajlarÄ±

MCP protokolÃ¼ **uygulama katmanÄ±nda** Ã§alÄ±ÅŸan bir protokoldÃ¼r. Yani OSI modeline gÃ¶re bakÄ±ldÄ±ÄŸÄ±nda, TCP/IP gibi taÅŸÄ±ma katmanÄ± protokollerinin Ã¼zerinde konumlanÄ±r ve uygulamalar arasÄ± veri alÄ±ÅŸveriÅŸinin anlamÄ±nÄ± tanÄ±mlar. Bu yÃ¼ksek seviyeli konum, MCPâ€™ye Ã¶nemli avantajlar kazandÄ±rmaktadÄ±r. Ã–ncelikle, uygulama katmanÄ± protokolÃ¼ olduÄŸu iÃ§in MCP mesajlarÄ± **insan tarafÄ±ndan okunabilir JSON** formatÄ±nda tanÄ±mlanmÄ±ÅŸtÄ±r ve bu sayede dil agnostik bir ÅŸekilde birden fazla programlama dilinde kolaylÄ±kla uygulanabilir (nitekim halihazÄ±rda MCP iÃ§in Python, TypeScript, Java, C#, Go, Rust gibi farklÄ± dillerde SDKâ€™lar mevcuttur). Protokol mesajlarÄ±nÄ±n JSON-RPC standardÄ±nÄ± kullanmasÄ±, yapÄ±landÄ±rÄ±lmÄ±ÅŸ bir iletiÅŸim saÄŸlayarak hem istemci hem sunucu tarafÄ±nda uygulanmasÄ±nÄ± ve hata ayÄ±klamasÄ±nÄ± kolaylaÅŸtÄ±rÄ±r.

MCPâ€™nin taÅŸÄ±ma baÄŸÄ±msÄ±z bir Ã¼st dÃ¼zey protokol olarak tasarlanmÄ±ÅŸ olmasÄ±, **esneklik** ve **uyumluluk** avantajÄ± saÄŸlar. Protokol, altÄ±nda yatan taÅŸÄ±ma katmanÄ±nÄ± soyutlayabildiÄŸi iÃ§in aynÄ± veri yapÄ±sÄ±nÄ± ister yerel ister uzak senaryolarda iletebilir. Ã–rneÄŸin, bir geliÅŸtirici MCP sunucusunu baÅŸlangÄ±Ã§ta yerel STDIO modunda Ã§alÄ±ÅŸtÄ±rÄ±p test edebilir; daha sonra minimal deÄŸiÅŸiklikle aynÄ± sunucuyu uzak bir HTTP servis olarak daÄŸÄ±tabilir. Bu sayede protokol, geliÅŸen ihtiyaÃ§lara gÃ¶re Ã¶lÃ§eklenebilir bir yapÄ± sunar. AyrÄ±ca MCP, doÄŸrudan IP seviyesinde yeni bir protokol icat etmeyip HTTP gibi yaygÄ±n bir uygulama protokolÃ¼nÃ¼ opsiyon olarak kullandÄ±ÄŸÄ± iÃ§in mevcut altyapÄ±larla **uyumludur** â€“ gÃ¼venlik duvarlarÄ±, yÃ¼k dengeleyiciler veya HTTPS ÅŸifrelemesi gibi halihazÄ±rda oturmuÅŸ mekanizmalarÄ± tekrar keÅŸfetmeye gerek kalmadan kullanabilir.

TaÅŸÄ±ma katmanÄ±nÄ±n soyutlanmasÄ±yla gelen bir diÄŸer avantaj, **gÃ¼venli iletiÅŸim ve kimlik doÄŸrulama konusunda standartlarÄ±n yeniden kullanÄ±lmasÄ±dÄ±r**. MCP, uzak sunucularla haberleÅŸirken HTTPS Ã¼zerinden Ã§alÄ±ÅŸarak TLS ÅŸifrelemesini devreye sokabilmekte ve HTTPâ€™nin oturmuÅŸ kimlik doÄŸrulama yÃ¶ntemlerini (OAuth eriÅŸim tokenlarÄ±, API anahtarlarÄ±, vb.) aynen kullanabilmektedir. Bu, protokolÃ¼n gÃ¼venlik konusunda gÃ¼venilir ve test edilmiÅŸ yÃ¶ntemlerden faydalanmasÄ±nÄ± saÄŸlar. Ã–rneÄŸin, Anthropic varsayÄ±lan olarak MCP yetkilendirmesi iÃ§in OAuth 2.0 tabanlÄ± bir token mekanizmasÄ±nÄ± Ã¶ngÃ¶rmÃ¼ÅŸtÃ¼r. Son kullanÄ±cÄ± aÃ§Ä±sÄ±ndan, MCP trafikleri tÄ±pkÄ± bir web trafiÄŸi gibi gÃ¼venli kanaldan akabildiÄŸi iÃ§in aÄŸ dinlemesi veya benzeri riskler azaltÄ±lmaktadÄ±r. Ã–te yandan yerel taÅŸÄ±ma seÃ§eneÄŸi (STDIO), aÄŸ Ã¼zerinden veri geÃ§irmediÄŸi iÃ§in Ã¶zellikle tek makine Ã¼zerinde Ã§alÄ±ÅŸan senaryolarda **azami performans ve gÃ¼venlik** (dÄ±ÅŸ saldÄ±rÄ± yÃ¼zeyinin olmamasÄ± nedeniyle) sunar.

Ã–zetle, MCPâ€™nin uygulama katmanÄ±nda konumlanmasÄ± ve altÄ±ndaki taÅŸÄ±ma katmanÄ±nÄ± esnek tutmasÄ± protokolÃ¼ geniÅŸ bir kullanÄ±m yelpazesinde pratik hale getirmektedir. Bu sayede hem *platform baÄŸÄ±msÄ±zlÄ±ÄŸÄ±* hem de *gÃ¼venlik ve performans* aÃ§Ä±sÄ±ndan geliÅŸtiricilere Ã¶nemli kolaylÄ±klar saÄŸlar.

### MCP'nin AÃ§Ä±k Kaynak YapÄ±sÄ±nÄ±n GÃ¼venliÄŸe Etkileri

MCP protokolÃ¼nÃ¼n **aÃ§Ä±k kaynak** olmasÄ±, gÃ¼venlik aÃ§Ä±sÄ±ndan Ã§ift yÃ¶nlÃ¼ etkilere sahiptir. Olumlu tarafta, protokolÃ¼n kaynak kodu ve spesifikasyonlarÄ±nÄ±n aÃ§Ä±k olmasÄ±, geniÅŸ bir topluluk tarafÄ±ndan incelenebilmesini ve katkÄ± yapÄ±labilmesini mÃ¼mkÃ¼n kÄ±lar. Nitekim MCP hÄ±zla popÃ¼lerlik kazanÄ±rken, Ã§eÅŸitli gÃ¼venlik araÅŸtÄ±rmacÄ±larÄ± ve ÅŸirketler de protokolÃ¼ mercek altÄ±na almÄ±ÅŸtÄ±r. Bu kolektif inceleme sayesinde protokoldeki potansiyel zayÄ±flÄ±klar erken aÅŸamada tespit edilip dÃ¼zeltilebilmektedir. Topluluk Ã¼yeleri mevcut yetkilendirme mekanizmasÄ±nÄ±n kurumsal uygulamalarla Ã§eliÅŸen noktalarÄ±nÄ± fark etmiÅŸ ve yetkilendirme spesifikasyonunun iyileÅŸtirilmesi iÃ§in giriÅŸimde bulunmuÅŸtur. Bu sayede, protokol geliÅŸtikÃ§e gÃ¼venlik boyutunda da gÃ¼ncel en iyi uygulamalarla uyumlu hale gelmesi saÄŸlanmaktadÄ±r.

AÃ§Ä±k kaynaÄŸÄ±n bir diÄŸer avantajÄ±, *gÃ¼venlikte ÅŸeffaflÄ±k* saÄŸlamasÄ±dÄ±r. MCP ekosistemindeki istemci ve sunucu uygulamalarÄ± aÃ§Ä±k kaynak kodlu olduÄŸu iÃ§in, geliÅŸtiriciler veya kurumlar bu kodlarÄ± inceleyerek iÃ§lerinde zararlÄ± bir iÅŸlev olup olmadÄ±ÄŸÄ±nÄ± denetleyebilir. KapalÄ± kutu bir yazÄ±lÄ±ma kÄ±yasla, aÃ§Ä±k kodlu bir MCP sunucusunun ne yaptÄ±ÄŸÄ± gÃ¶rÃ¼lebilir olduÄŸu iÃ§in sÃ¼rpriz istenmeyen davranÄ±ÅŸlar riski teorik olarak daha dÃ¼ÅŸÃ¼ktÃ¼r. DahasÄ±, ekosistemdeki popÃ¼ler MCP bileÅŸenleri genellikle dijital imza ile yayÄ±nlanmakta veya bÃ¼tÃ¼nlÃ¼k kontrolÃ¼ne tabi tutulmaktadÄ±r; bu da koda dÄ±ÅŸarÄ±dan zararlÄ± bir mÃ¼dahale yapÄ±lmadÄ±ÄŸÄ±nÄ± doÄŸrulamayÄ± mÃ¼mkÃ¼n kÄ±lar. GeliÅŸtiricilerin de kendi yayÄ±nladÄ±klarÄ± MCP sunucularÄ±nÄ± imzalamalarÄ± ve kullanÄ±cÄ±larÄ±n bu imzalarÄ± doÄŸrulamalarÄ± tavsiye edilmektedir.

Ã–te yandan, aÃ§Ä±k kaynak olmanÄ±n getirdiÄŸi bazÄ± **gÃ¼venlik riskleri** de vardÄ±r. Her ÅŸeyden Ã¶nce, MCP protokolÃ¼ tamamen aÃ§Ä±k bir ekosistem olduÄŸundan, kÃ¶tÃ¼ niyetli aktÃ¶rler de protokolÃ¼ kullanarak zararlÄ± MCP sunucularÄ± geliÅŸtirebilir ve bunlarÄ± topluluk iÃ§inde paylaÅŸabilir. Ã–rneÄŸin, bir saldÄ±rgan ilk bakÄ±ÅŸta yararlÄ± gÃ¶rÃ¼nen bir MCP sunucusu (belki bir hava durumu aracÄ± veya takvim aracÄ±) yayÄ±nlayÄ±p kullanÄ±cÄ±larÄ± bunu kurmaya ikna edebilir; ancak daha sonra bir gÃ¼ncelleme ile bu sunucuya gizlice hassas bilgileri toplayan veya yetkisiz komutlar Ã§alÄ±ÅŸtÄ±ran iÅŸlevler ekleyebilir. Bu tÃ¼r **â€œaraÃ§ enjeksiyonuâ€** diyebileceÄŸimiz senaryolarda, aÃ§Ä±k kaynak kod baÅŸlangÄ±Ã§ta temiz olsa bile ileride kasÄ±tlÄ± olarak suistimal edilebilir hale getirilebilir. Benzer ÅŸekilde, sunucunun tanÄ±ttÄ±ÄŸÄ± araÃ§larÄ±n ismini ve tanÄ±mÄ±nÄ± yanÄ±ltÄ±cÄ± seÃ§mek de mÃ¼mkÃ¼n olduÄŸundan, kÃ¶tÃ¼ niyetli bir geliÅŸtirici masum gÃ¶rÃ¼nen bir aracÄ± aslÄ±nda farklÄ± ve tehlikeli iÅŸler yapmak iÃ§in tasarlayabilir. AÃ§Ä±k kaynak dÃ¼nyasÄ±nda kullanÄ±cÄ±larÄ±n her bulduklarÄ± projeye gÃ¼venmemeleri, Ã¶zellikle de MCP gibi *kod Ã§alÄ±ÅŸtÄ±rma yeteneÄŸi olan* sunucular sÃ¶z konusuysa, son derece kritiktir.

AÃ§Ä±k kaynaÄŸÄ±n bir diÄŸer zorluÄŸu da **tedarik zinciri gÃ¼venliÄŸi** ile ilgilidir. MCP istemci ve sunucularÄ± da sonuÃ§ta yazÄ±lÄ±m bileÅŸenleridir ve paket yÃ¶netim sistemleri Ã¼zerinden daÄŸÄ±tÄ±lÄ±r. SaldÄ±rganlar popÃ¼ler MCP paketlerinin isimlerini taklit eden (typosquatting) zararlÄ± paketler yayÄ±nlayabilir veya geliÅŸtiricilerin hesaplarÄ±nÄ± ele geÃ§irip zararlÄ± gÃ¼ncellemeler Ã§Ä±karabilir. Bu risk, genel olarak tÃ¼m aÃ§Ä±k kaynak projelerinde mevcuttur ve MCP de bir istisna deÄŸildir. Nitekim, MCP bileÅŸenlerinin gÃ¼venliÄŸi iÃ§in tavsiye edilen uygulamalar arasÄ±nda *Statik Kod Analizi (SAST)* ve *YazÄ±lÄ±m BileÅŸeni Analizi (SCA)* araÃ§larÄ±nÄ±n kullanÄ±lmasÄ±, baÄŸÄ±mlÄ±lÄ±klarÄ±n bilinen zafiyetlere karÅŸÄ± taranmasÄ± gibi sÃ¼reÃ§ler sayÄ±lmaktadÄ±r. Proje geliÅŸtirme sÃ¼reÃ§lerinde bu tÃ¼r gÃ¼venlik denetimlerinin uygulanmasÄ±, aÃ§Ä±k kaynak olmanÄ±n getirdiÄŸi riskleri azaltmaya yardÄ±mcÄ± olur.

SonuÃ§ olarak, MCPâ€™nin aÃ§Ä±k kaynak yapÄ±sÄ± gÃ¼venlikte hem bir **imkan** hem de bir **sorumluluk** doÄŸurmaktadÄ±r. DoÄŸru yÃ¶netildiÄŸinde, geniÅŸ bir katÄ±lÄ±mcÄ± kitlesinin katkÄ±sÄ±yla daha gÃ¼venli bir protokol geliÅŸimi mÃ¼mkÃ¼n olmakta; ancak bu aÃ§Ä±klÄ±k aynÄ± zamanda suistimale aÃ§Ä±k bir ekosistem yarattÄ±ÄŸÄ± iÃ§in, kullanÄ±cÄ±larÄ±n ve geliÅŸtiricilerin gÃ¼venlik farkÄ±ndalÄ±ÄŸÄ±nÄ±n yÃ¼ksek olmasÄ± gerekmektedir.

### Potansiyel SaldÄ±rÄ± SenaryolarÄ±

MCP protokolÃ¼ ve onu kullanan uygulamalar, tasarÄ±m itibariyle Ã§eÅŸitli saldÄ±rÄ± tÃ¼rlerine maruz kalabilir. Bu bÃ¶lÃ¼mde, Ã¶zellikle **Ortadaki Adam (Man-in-the-Middle)**, **Replay (Yeniden Oynatma)** ve **Enjeksiyon** saldÄ±rÄ± vektÃ¶rleri Ã¼zerinde durulacaktÄ±r:

* **Ortadaki Adam SaldÄ±rÄ±sÄ± (MITM):** Bir MITM saldÄ±rÄ±sÄ±nda, saldÄ±rgan istemci ile sunucu arasÄ±ndaki trafiÄŸi gizlice dinleyip deÄŸiÅŸtirebilir. MCP, uzak sunucu baÄŸlantÄ±larÄ±nda HTTP tabanlÄ± iletiÅŸim kullandÄ±ÄŸÄ± iÃ§in, **ÅŸifrelenmemiÅŸ bir baÄŸlantÄ± (HTTP)** Ã¼zerinden iletiÅŸim kurulursa ciddi bir MITM riski oluÅŸur. Ã–rneÄŸin, yerel aÄŸda bir saldÄ±rgan MCP istemcisinin sunucuya giden trafiÄŸini yakalayÄ±p baÅŸka bir sunucuya yÃ¶nlendirebilir veya iÃ§erik enjeksiyonu yapabilir. Bu nedenle MCP kullanÄ±mÄ±nda **TLS ÅŸifrelemesi (HTTPS)** ÅŸarttÄ±r; aksi halde oturum aÃ§Ä±lÄ±ÅŸ bilgilerinden, iletilen baÄŸlam verisine kadar her ÅŸey Ã¼Ã§Ã¼ncÃ¼ ÅŸahÄ±slarca gÃ¶rÃ¼lebilir veya deÄŸiÅŸtirilebilir. MITM sadece gizli dinleme deÄŸil, aynÄ± zamanda istemci ile sunucu arasÄ±na girerek sahte yanÄ±tlar verme veya istemciden gelen isteÄŸi bloklama gibi etkiler de yaratabilir. Uzak sunucularla iletiÅŸimde HTTPS kullanmak ve sunucu sertifikasÄ±nÄ± doÄŸrulamak, bu tÃ¼r saldÄ±rÄ±larÄ±n Ã¶nlenmesinde temel Ã¶nlemdir.

* **Replay SaldÄ±rÄ±larÄ±:** Replay (yeniden oynatma) saldÄ±rÄ±sÄ±nda, aÄŸ trafiÄŸini yakalayan bir saldÄ±rgan daha sonra bu trafiÄŸi tekrar gÃ¶ndererek sistemi kandÄ±rmaya Ã§alÄ±ÅŸÄ±r. MCP protokolÃ¼nde istemci-sunucu mesajlarÄ± genellikle belirli bir isteÄŸe yanÄ±t iliÅŸkisi iÃ§inde olduÄŸundan ve protokol durumsal bir oturum yapÄ±sÄ± barÄ±ndÄ±rdÄ±ÄŸÄ±ndan, klasik anlamda replay yapmanÄ±n etkisi sÄ±nÄ±rlÄ± olabilir. Ancak Ã¶zellikle kimlik doÄŸrulama veya yetki bilgilerinin tekrar kullanÄ±lmasÄ± riski her zaman vardÄ±r. Ã–rneÄŸin bir saldÄ±rgan, bir MCP isteÄŸini Ã¼zerindeki OAuth eriÅŸim jetonu ile birlikte ele geÃ§irirse, bu isteÄŸi deÄŸiÅŸtirip yeniden gÃ¶ndermek suretiyle istenmeyen iÅŸlemler yaptÄ±rabilir. MCP spesifikasyonunda versiyon pazarlÄ±ÄŸÄ± ve oturum baÅŸlatma mekanizmalarÄ± olsa da, **anti-replay iÃ§in Ã¶zel bir nonce veya zaman damgasÄ± kullandÄ±ÄŸÄ±na dair** aÃ§Ä±k bir bilgi olmayabilir. DolayÄ±sÄ±yla replay riskinin esasen **taÅŸÄ±ma katmanÄ±nÄ±n gÃ¼venliÄŸi** ile bertaraf edildiÄŸini varsayabiliriz (Ã¶rn. TLS iÃ§indeki oturum kimliÄŸi ve kÄ±sa Ã¶mÃ¼rlÃ¼ token kullanÄ±mÄ±). Yine de, MCP sunucularÄ±nÄ±n kritik iÅŸlemler iÃ§in isteklerin tekilliÄŸini kontrol etmesi veya aynÄ± tokenâ€™Ä±n art arda kullanÄ±mÄ±nÄ± kÄ±sÄ±tlamasÄ± gibi Ã¶nlemler dÃ¼ÅŸÃ¼nÃ¼lebilir. SonuÃ§ itibariyle, replay saldÄ±rÄ±larÄ±na karÅŸÄ± **en iyi savunma**, trafiÄŸin ÅŸifrelenmesi ve geÃ§erlilik sÃ¼resi sÄ±nÄ±rlÄ±, tek seferlik yetkilendirme jetonlarÄ± kullanÄ±lmasÄ±dÄ±r.

* **Enjeksiyon SaldÄ±rÄ±larÄ±:** MCP ekosisteminde *enjeksiyon* kavramÄ± birden fazla boyutta karÅŸÄ±mÄ±za Ã§Ä±kar:

  * **Komut Enjeksiyonu:** BirÃ§ok MCP sunucusu, alt seviyede kabuk komutlarÄ± veya sistem Ã§aÄŸrÄ±larÄ± Ã§alÄ±ÅŸtÄ±rarak gÃ¶revlerini yerine getirir (Ã¶zellikle yerel sunucular). EÄŸer sunucu, kullanÄ±cÄ±dan veya LLMâ€™den gelen girdileri uygun ÅŸekilde filtrelemez ve doÄŸrudan bir komut satÄ±rÄ±na aktarÄ±rsa, saldÄ±rganlar bu durumu **komut enjeksiyonu** iÃ§in kullanabilir. Ã–rneÄŸin, bazÄ± MCP sunucu kodlarÄ±nda, kullanÄ±cÄ± bildirim baÅŸlÄ±ÄŸÄ± oluÅŸturulurken gelen deÄŸerin doÄŸrudan `notify-send` komutuna parametre verildiÄŸi gÃ¶rÃ¼lebilir; burada yeterli denetim olmadÄ±ÄŸÄ±ndan potansiyel bir komut enjeksiyonu aÃ§Ä±klÄ±ÄŸÄ± oluÅŸabilir. KÃ¶tÃ¼ niyetli bir aktÃ¶r, Ã¶zel hazÄ±rlanmÄ±ÅŸ girdilerle bu aÃ§Ä±ÄŸÄ± tetikleyerek sunucunun yetkileriyle rastgele komutlar Ã§alÄ±ÅŸtÄ±rabilir. Bu tÃ¼r vakalar, Ã¶zellikle yerel MCP sunucularÄ±nÄ±n kullanÄ±cÄ± hesabÄ± haklarÄ±yla Ã§alÄ±ÅŸtÄ±ÄŸÄ± senaryolarda **tam sistem tehlikeye atÄ±lmasÄ±** ile sonuÃ§lanabilir. DolayÄ±sÄ±yla MCP sunucusu geliÅŸtiricilerinin, Ã§alÄ±ÅŸtÄ±rdÄ±klarÄ± komutlarÄ± ve bu komutlara verdikleri argÃ¼manlarÄ± Ã§ok sÄ±kÄ± ÅŸekilde denetlemeleri, gerekirse girilen deÄŸerleri beyaz liste yÃ¶ntemiyle filtrelemeleri kritiktir. AyrÄ±ca, yerel sunucularÄ±n bir **sandbox (korunaklÄ± ortam)** iÃ§inde, eriÅŸim izinleri kÄ±sÄ±tlanmÄ±ÅŸ ÅŸekilde Ã§alÄ±ÅŸtÄ±rÄ±lmasÄ± Ã¶nerilmektedir.
  * **Prompt Enjeksiyonu:** Bu saldÄ±rÄ± tÃ¼rÃ¼ doÄŸrudan protokolÃ¼n teknik altyapÄ±sÄ±nÄ± deÄŸil, LLMâ€™nin zafiyetini hedef alÄ±r ancak MCP baÄŸlamÄ±nda Ã¶zel bir Ã¶nem kazanÄ±r. MCP, LLMâ€™nin dÄ±ÅŸ araÃ§larÄ± kullanmasÄ±na olanak saÄŸladÄ±ÄŸÄ± iÃ§in, kÃ¶tÃ¼ niyetli bir yÃ¶nlendirme (prompt) ile LLMâ€™yi tehlikeli bir aracÄ± Ã§alÄ±ÅŸtÄ±rmaya ikna etmek mÃ¼mkÃ¼n hale gelebilir. Ã–rneÄŸin, bir saldÄ±rgan kullanÄ±cÄ±yÄ± kandÄ±rarak MCP istemcisine girdiÄŸi komutun iÃ§ine gizlenmiÅŸ zararlÄ± bir talimat koydurabilir. LLM bu girdiyle Ã§alÄ±ÅŸÄ±rken, gÃ¶rÃ¼nÃ¼rde masum gÃ¶rÃ¼nen isteÄŸi gerÃ§ekleÅŸtirmenin yanÄ±nda saldÄ±rganÄ±n arzusuyla ek bir iÅŸlem de baÅŸlatabilir (Ã¶rneÄŸin, â€œtalep edilen yeni kullanÄ±cÄ± hesabÄ±nÄ± oluÅŸturmanÄ±nâ€ yanÄ± sÄ±ra bir de saldÄ±rgan iÃ§in yÃ¼ksek yetkili bir hesap oluÅŸturma). Bu tÃ¼r prompt enjeksiyonlarÄ±, Ã¶zellikle LLM yanÄ±tlarÄ±na koÅŸulsuz gÃ¼venilip kullanÄ±cÄ± onayÄ± aranmadan eyleme dÃ¶kÃ¼ldÃ¼ÄŸÃ¼nde ciddi hasarlara yol aÃ§abilir. Bu nedenle, MCP istemcileri kritik iÅŸlemleri gerÃ§ekleÅŸtirmeden Ã¶nce mÃ¼mkÃ¼n olduÄŸunca **kullanÄ±cÄ±dan onay almalÄ±dÄ±r** veya LLM'nin yapabileceklerini kÄ±sÄ±tlayacak politikalar uygulamalÄ±dÄ±r.
  * **AraÃ§ (Tool) Enjeksiyonu:** YukarÄ±da aÃ§Ä±k kaynak riskleri kÄ±smÄ±nda deÄŸinilen senaryonun bir parÃ§asÄ± olarak, MCP sunucularÄ±nÄ±n tanÄ±ttÄ±ÄŸÄ± araÃ§lar suistimal edilebilir. Bu saldÄ±rÄ±, bir bakÄ±ma *supply chain* sorunuyla birleÅŸir; bir saldÄ±rgan, saÄŸladÄ±ÄŸÄ± aracÄ±n masum fonksiyonunu daha sonra gÃ¼ncelleyerek kullanÄ±cÄ±ya zarar verecek hale getirebilir. Ã–rneÄŸin, baÅŸlangÄ±Ã§ta sadece hava durumu bilgisini dÃ¶ndÃ¼ren bir araÃ§, ileride gÃ¼ncellemeyle kullanÄ±cÄ± verilerini Ã§alan bir kod parÃ§asÄ±na dÃ¶nÃ¼ÅŸtÃ¼rÃ¼lebilir. LLM, aracÄ±n aÃ§Ä±klamasÄ±na gÃ¼venerek onu kullanacaÄŸÄ± iÃ§in, bu durumda saldÄ±rgan arka planda kÃ¶tÃ¼ faaliyetine devam ederken, kullanÄ±cÄ± ve istemci tarafÄ± yalnÄ±zca aracÄ±n normal Ã§Ä±ktÄ±sÄ±nÄ± gÃ¶rÃ¼p aldatÄ±labilir. Bu nedenle, MCP istemcilerinin kurulu sunucularÄ±n kod veya davranÄ±ÅŸ deÄŸiÅŸikliklerini izleyebilmesi, versiyon kilitleme (*pinning*) yaparak beklenmedik gÃ¼ncellemeleri engellemesi ve kullanÄ±cÄ±yÄ± bilgilendirmesi Ã¶nemli bir koruma yÃ¶ntemidir.

YukarÄ±daki saldÄ±rÄ± tÃ¼rleri MCP protokolÃ¼nÃ¼n farklÄ± bileÅŸenlerini hedef almakla birlikte, ortak nokta olarak *MCP kullanÄ±mÄ±nda gÃ¼venlik bilincinin Ã¶nemini* ortaya koymaktadÄ±r. Gerek altyapÄ±sal (Ã¶r. MITM, replay) gerek uygulama seviyesinde (enjeksiyon) olsun, protokolÃ¼ kullanÄ±rken uygun Ã¶nlemler alÄ±nmadÄ±ÄŸÄ± takdirde istenmeyen sonuÃ§larla karÅŸÄ±laÅŸmak olasÄ±dÄ±r.

### MCP ProtokolÃ¼ndeki Mevcut GÃ¼venlik Ã–nlemleri ve DeÄŸerlendirmesi

Anthropic (soruda bahsedilen adÄ±yla *Antopic*), MCP protokolÃ¼nÃ¼ tasarlarken bazÄ± temel gÃ¼venlik Ã¶nlemlerini dahil etmiÅŸtir. BunlarÄ±n baÅŸÄ±nda, protokolÃ¼n **kimlik doÄŸrulama ve yetkilendirme mekanizmasÄ±** gelir. MCP, uzak sunucular iÃ§in OAuth 2.0 tabanlÄ± eriÅŸim tokenâ€™larÄ± kullanÄ±lmasÄ±nÄ± Ã¶nererek, her istemci-sunucu baÄŸlantÄ±sÄ±nÄ±n bir yetki kontrolÃ¼ne tabi olmasÄ±nÄ± saÄŸlamaya Ã§alÄ±ÅŸÄ±r. Bu sayede, her MCP sunucusu eylemini bir kullanÄ±cÄ± veya uygulama adÄ±na gerÃ§ekleÅŸtirecekse, Ã¶nceden alÄ±nmÄ±ÅŸ bir eriÅŸim iznine sahip olmasÄ± beklenir. Ancak burada Ã¶nemli bir nokta, mevcut spesifikasyondaki OAuth kullanÄ±m detaylarÄ±nÄ±n her senaryoya uymayabileceÄŸinin ortaya Ã§Ä±kmÄ±ÅŸ olmasÄ±dÄ±r. Topluluktan gelen geri bildirimlere gÃ¶re MCPâ€™nin ilk yetkilendirme tanÄ±mÄ±, kurumsal ortamlardaki bazÄ± modern uygulamalarla Ã§eliÅŸmektedir ve bu konuda resmi spesifikasyonun gÃ¼ncellenmesi gÃ¼ndemdedir. Bu durum, protokolÃ¼n yetkilendirme boyutunda henÃ¼z tam olgunlaÅŸmadÄ±ÄŸÄ±nÄ± ve geliÅŸtirilmeye aÃ§Ä±k yanlar olduÄŸunu gÃ¶stermektedir.

Bir diÄŸer yerleÅŸik gÃ¼venlik Ã¶nlemi, **iletiÅŸimin ÅŸifrelenmesi** ile ilgilidir. Her ne kadar MCP doÄŸrudan â€œÅŸifreleme zorunluluÄŸuâ€nu kendi iÃ§inde dayatmasa da (zira bu genellikle taÅŸÄ±ma katmanÄ±nÄ±n sorumluluÄŸudur), dokÃ¼mantasyon ve topluluk rehberlerinde uzak baÄŸlantÄ±lar iÃ§in TLS destekli HTTPS kullanÄ±lmasÄ±nÄ±n altÄ± Ã§izilir. Ã–zellikle GitHub gibi MCP kullanan platformlar, kendi sunucularÄ± ile istemci arasÄ±ndaki etkileÅŸimlerde gÃ¼venlik iÃ§in ek mekanizmalar uygulamÄ±ÅŸtÄ±r. Ã–rneÄŸin GitHubâ€™Ä±n MCP sunucusu (Copilot ile entegrasyon amaÃ§lÄ±), paylaÅŸÄ±lan depo verilerinde gizli anahtarlarÄ±n aÃ§Ä±ÄŸa Ã§Ä±kmasÄ±nÄ± Ã¶nlemek iÃ§in â€œpush protectionâ€ adlÄ± bir gÃ¼venlik filtresi kullanÄ±r; bu filtre sayesinde MCP Ã¼zerinden gerÃ§ekleÅŸtirilen eylemlerde hassas verilerin sÄ±zmasÄ± engellenir. Bu tÃ¼r Ã¶nlemler MCP protokolÃ¼nÃ¼n parÃ§asÄ± olmasa da, onu kullanan hizmetlerin kendi gÃ¼venlik katmanlarÄ±nÄ± eklediÄŸini gÃ¶stermektedir.

Anthropicâ€™in MCP iÃ§in geliÅŸtirdiÄŸi referans sunucularda da bazÄ± gÃ¼venlik dÃ¼ÅŸÃ¼nceleri mevcuttur. Ã–rneÄŸin, yerel dosya sistemi sunucusu belli bir dizin altÄ±nda eriÅŸime izin vererek bir tÃ¼r *sandbox* yaratmayÄ± hedefler. Ancak yapÄ±lan baÄŸÄ±msÄ±z gÃ¼venlik analizleri, bu yaklaÅŸÄ±mÄ±n kusursuz olmadÄ±ÄŸÄ±nÄ± ortaya koymuÅŸtur. BazÄ± gÃ¼venlik araÅŸtÄ±rmalarÄ±, resmi dosya sistemi MCP sunucusunda dizin atlama veya sembolik baÄŸ (symlink) yoluyla kÄ±sÄ±tlamalarÄ±n atlatÄ±labildiÄŸini ve bunun sunucunun Ã§alÄ±ÅŸtÄ±ÄŸÄ± sistemde daha geniÅŸ eriÅŸimlere yol aÃ§abildiÄŸini gÃ¶stermiÅŸtir. Bu bulgular, Anthropicâ€™in koyduÄŸu gÃ¼venlik Ã¶nlemlerinin (dizin kÄ±sÄ±tlamasÄ± gibi) tek baÅŸÄ±na yeterli olmadÄ±ÄŸÄ±nÄ± gÃ¶stermiÅŸtir. Ã–zellikle LLM tabanlÄ± araÃ§larÄ±n Ã§oÄŸunlukla geliÅŸtirici rahatlÄ±ÄŸÄ± iÃ§in yÃ¼ksek ayrÄ±calÄ±klarla (Ã¶rn. kullanÄ±cÄ± oturumunda veya bazen yÃ¶netici haklarÄ±yla) Ã§alÄ±ÅŸtÄ±rÄ±ldÄ±ÄŸÄ± dÃ¼ÅŸÃ¼nÃ¼lÃ¼rse, bu tip aÃ§Ä±klar kÃ¶tÃ¼ye kullanÄ±ldÄ±ÄŸÄ±nda **sistem bÃ¼tÃ¼nlÃ¼ÄŸÃ¼nÃ¼ ciddi ÅŸekilde tehlikeye atmaktadÄ±r**.

Bununla birlikte, olumlu tarafÄ±ndan bakÄ±ldÄ±ÄŸÄ±nda Anthropic ve genel olarak MCP topluluÄŸu gÃ¼venlik aÃ§Ä±klarÄ±na oldukÃ§a hÄ±zlÄ± reaksiyon vermektedir. Ã–rneÄŸin bazÄ± projelerde bildirilmiÅŸ uzaktan kod Ã§alÄ±ÅŸtÄ±rma aÃ§Ä±klarÄ±, proje geliÅŸtiricileri tarafÄ±ndan kÄ±sa sÃ¼rede yamanmÄ±ÅŸtÄ±r. AynÄ± ÅŸekilde Ã§eÅŸitli sandbox kaÃ§Ä±ÅŸÄ± sorunlarÄ±na karÅŸÄ± da ilgili yamalar ve kullanÄ±cÄ±lara yÃ¶nelik uyarÄ±lar yayÄ±nlanmÄ±ÅŸtÄ±r. Bu durum, MCP ekosisteminin gÃ¼venlik konusunu ciddiye aldÄ±ÄŸÄ±nÄ± ve proaktif iyileÅŸtirmelere gittiÄŸini gÃ¶stermektedir. Yine de, henÃ¼z genÃ§ sayÄ±labilecek bu protokol iÃ§in mevcut gÃ¼venlik Ã¶nlemlerinin *â€œyeterliâ€* olduÄŸunu sÃ¶ylemek zordur. Ortaya Ã§Ä±kan her yeni kullanÄ±m senaryosu veya sunucu uygulamasÄ±, kendine Ã¶zgÃ¼ gÃ¼venlik aÃ§Ä±klarÄ± barÄ±ndÄ±rabilir. Anthropicâ€™in baÅŸlangÄ±Ã§ta protokole dahil ettiÄŸi temel gÃ¼venlik kavramlarÄ± (OAuth ile yetkilendirme, JSON-RPC ile yapÄ±landÄ±rÄ±lmÄ±ÅŸ ileti vb.) Ã¶nemli bir zemin saÄŸlasa da, gerÃ§ek dÃ¼nyadaki saldÄ±rÄ± senaryolarÄ± bu Ã¶nlemlerin etrafÄ±ndan dolaÅŸmanÄ±n yollarÄ±nÄ± bulmuÅŸtur. Ã–zetle, **MCPâ€™nin gÃ¼venliÄŸi hala evrim geÃ§irmektedir**; mevcut Ã¶nlemler bazÄ± tehditleri azaltmakla birlikte, protokolÃ¼n tam anlamÄ±yla gÃ¼venli kabul edilebilmesi iÃ§in sÃ¼rekli gÃ¶zden geÃ§irme, test etme ve gÃ¼ncelleme gerekmektedir.

### GeliÅŸtiriciler ve Kurumlar Ä°Ã§in GÃ¼venli MCP Uygulama Ã–nerileri

MCP protokolÃ¼nÃ¼ gÃ¼venli bir biÃ§imde uygulamak ve kullanmak isteyen geliÅŸtiriciler ile kurumlar, aÅŸaÄŸÄ±daki Ã¶nlemleri gÃ¶z Ã¶nÃ¼nde bulundurmalÄ±dÄ±r:

* **GÃ¼venli Ä°letiÅŸim ve Sertifika DoÄŸrulamasÄ±:** Uzak MCP sunucularÄ±yla haberleÅŸirken daima HTTPS protokolÃ¼ kullanÄ±n ve sunucu sertifikasÄ±nÄ±n doÄŸrulandÄ±ÄŸÄ±ndan emin olun. ÅifrelenmemiÅŸ HTTP Ã¼zerinden asla hassas veri iletmeyin; aksi halde MITM saldÄ±rÄ±larÄ±na aÃ§Ä±k hale gelirsiniz. Gerekirse istemci tarafÄ±nda, sunucu URLâ€™sinin `https://` ile baÅŸlamadÄ±ÄŸÄ±nÄ± fark edince baÄŸlantÄ±yÄ± reddeden kontroller ekleyin.
* **GÃ¼Ã§lÃ¼ Kimlik DoÄŸrulama ve Yetkilendirme:** MCP sunucularÄ±na eriÅŸim iÃ§in mÃ¼mkÃ¼nse OAuth 2.0 gibi ispatlanmÄ±ÅŸ yÃ¶ntemlerle alÄ±nan eriÅŸim tokenâ€™larÄ± kullanÄ±n. Her sunucunun eriÅŸim tokenâ€™Ä±na sadece gerekli asgari yetkileri (scopelarÄ±) tanÄ±yÄ±n (Ã¶rneÄŸin bir dosya sistemi sunucusuna salt okunur eriÅŸim izni vermek gibi). â€œEn az ayrÄ±calÄ±kâ€ ilkesini gÃ¶zetin; bir MCP sunucusunun kullanÄ±cÄ± adÄ±na yapabileceÄŸi iÅŸlemleri kÄ±sÄ±tlayÄ±n. AyrÄ±ca, bir istemci bir sunucuya eriÅŸirken tek oturumluk veya kÄ±sa Ã¶mÃ¼rlÃ¼ tokenâ€™lar kullanmayÄ±, bunlarÄ± dÃ¼zenli olarak yenilemeyi ihmal etmeyin.
* **GÃ¼venilmeyen Sunuculara KarÅŸÄ± Tedbir:** YalnÄ±zca gÃ¼vendiÄŸiniz kaynaklardan gelen MCP sunucularÄ±nÄ± yÃ¼kleyin veya baÄŸlanÄ±n. Topluluk tarafÄ±ndan pek incelenmemiÅŸ, rastgele depolardan gelen sunucu uygulamalarÄ±nÄ± kullanmak risklidir. Kurum iÃ§inde MCP kullanÄ±lacaksa, **onaylÄ± bir sunucu listesi** oluÅŸturarak kullanÄ±cÄ±larÄ±n sadece bu sunuculara baÄŸlanmasÄ±na izin verin. MCP istemci uygulamanÄ±z, baÄŸlanÄ±lan sunucunun kimliÄŸini (Ã¶rneÄŸin dijital imza veya hash doÄŸrulamasÄ± ile) kontrol edebiliyorsa bu Ã¶zelliÄŸi etkinleÅŸtirin.
* **Kod BÃ¼tÃ¼nlÃ¼ÄŸÃ¼ ve GÃ¼ncellemeler:** MCP sunucu ve istemci yazÄ±lÄ±mlarÄ±nÄ±zÄ±n bÃ¼tÃ¼nlÃ¼ÄŸÃ¼nÃ¼ ve gÃ¼ncelliÄŸini koruyun. Kendi geliÅŸtirdiÄŸiniz MCP sunucularÄ±nÄ± dijital olarak imzalayÄ±n ve kullanÄ±cÄ±larÄ±n indirdiÄŸi kodun bu imzayla eÅŸleÅŸtiÄŸini doÄŸrulayÄ±n. KullandÄ±ÄŸÄ±nÄ±z MCP bileÅŸenlerinde Ã§Ä±kan gÃ¼venlik gÃ¼ncellemelerini yakÄ±ndan takip edin ve gecikmeden uygulayÄ±n. Standart bir **zafiyet yÃ¶netimi** sÃ¼reci dahilinde, MCP ile ilgili kÃ¼tÃ¼phaneleri ve araÃ§larÄ± belirli aralÄ±klarla tarayÄ±p bilinen aÃ§Ä±klar iÃ§in yamalarÄ± geÃ§irin.
* **GÃ¼venli Kod GeliÅŸtirme Prensipleri:** Bir MCP sunucusu geliÅŸtiriyorsanÄ±z, kullanÄ±cÄ±lardan veya LLMâ€™den alacaÄŸÄ±nÄ±z her girdiÄŸin potansiyel olarak zararlÄ± olabileceÄŸini varsayÄ±n. Ã–zellikle komut satÄ±rÄ± Ã§aÄŸrÄ±larÄ±, dosya eriÅŸimleri gibi iÅŸlemleri gerÃ§ekleÅŸtirirken girdi validasyonuna Ã¶nem verin. Parametreleri sistem komutlarÄ±na iletmeden Ã¶nce boÅŸluk, noktalÄ± virgÃ¼l, ampersand gibi komut ayrÄ±ÅŸtÄ±rÄ±cÄ± karakterlerden arÄ±ndÄ±rÄ±n veya bu karakterlere izin vermeyin. SQL sorgularÄ±, kabuk komutlarÄ± veya iÅŸletim sistemi APIâ€™leri Ã§aÄŸrÄ±larÄ± yapÄ±yorsanÄ±z **enjeksiyon karÅŸÄ±tÄ±** gÃ¼venlik kalÄ±plarÄ±nÄ± uygulayÄ±n (Ã¶rn. parametreli sorgular, sabit argÃ¼man listeleri vb.). AyrÄ±ca, derleme ve CI sÃ¼reÃ§lerinize statik kod analizi araÃ§larÄ± entegre ederek zayÄ±flÄ±klarÄ± daha kod yazÄ±m aÅŸamasÄ±nda yakalamaya Ã§alÄ±ÅŸÄ±n.
* **Sandbox ve AyÄ±rÄ±lmÄ±ÅŸ Haklar:** MÃ¼mkÃ¼n olan her durumda, MCP sunucularÄ±nÄ± izole bir ortama hapsedin. Ã–rneÄŸin bir dosya sistemi MCP sunucusu, sadece belli bir klasÃ¶r altÄ±nda okuma/yazma yapabilecek ÅŸekilde *chroot/jail* ortamÄ±nda veya konteyner iÃ§inde Ã§alÄ±ÅŸtÄ±rÄ±lmalÄ±dÄ±r. Ä°ÅŸletim sistemi seviyesinde bu sunuculara ayrÄ± kullanÄ±cÄ± hesaplarÄ± tahsis etmek ve bu hesaplara minimum yetkileri vermek etkili bir yÃ¶ntemdir. BÃ¶ylece, olasÄ± bir saldÄ±rÄ±da sunucunun yapabilecekleri kÄ±sÄ±tlanmÄ±ÅŸ olacaktÄ±r ve sistem geneline yayÄ±lmasÄ± engellenir.
* **KullanÄ±cÄ± OnayÄ± ve Denetim MekanizmalarÄ±:** MCP istemcisi tarafÄ±nda, LLMâ€™nin tetiklediÄŸi yÃ¼ksek riskli eylemler iÃ§in mutlaka kullanÄ±cÄ±nÄ±n onayÄ±nÄ± alacak bir adÄ±m ekleyin. Ã–rneÄŸin, dosya silme, yeni kullanÄ±cÄ± oluÅŸturma, para transferi gibi kritik bir iÅŸlem bir araÃ§ ile yapÄ±lacaksa, LLM bunu istese dahi kullanÄ±cÄ±dan â€œOnaylÄ±yor musunuz?â€ ÅŸeklinde bir geri bildirim almadan yÃ¼rÃ¼tmeyin. Bu, olasÄ± prompt enjeksiyonu vakalarÄ±nda istenmeyen sonuÃ§larÄ± Ã¶nlemek iÃ§in son savunma hattÄ±dÄ±r. Benzer ÅŸekilde, MCP istemciniz gerÃ§ekleÅŸtirilen iÅŸlemleri kullanÄ±cÄ±ya Ã¶zetleyebiliyorsa (gÃ¶rev tamamlandÄ±ÄŸÄ±nda â€œSunucu X ÅŸu iÅŸlemi gerÃ§ekleÅŸtirdiâ€ gibi), bu ÅŸeffaflÄ±k kullanÄ±cÄ±yÄ± gÃ¼vende tutmaya yardÄ±mcÄ± olacaktÄ±r.
* **KayÄ±t ve Ä°zleme:** MCP sunucularÄ±nÄ±n yaptÄ±ÄŸÄ± iÅŸlemleri merkezi bir gÃ¼nlÃ¼k (log) sistemine kaydetmesi veya en azÄ±ndan yerel olarak log tutmasÄ± Ã§ok Ã¶nemlidir. BÃ¶ylece, geriye dÃ¶nÃ¼k bir inceleme gerektiÄŸinde hangi komutlarÄ±n Ã§alÄ±ÅŸtÄ±rÄ±ldÄ±ÄŸÄ±, hangi kaynaklara eriÅŸildiÄŸi tespit edilebilir. Kurumlar, MCP aracÄ±lÄ±ÄŸÄ±yla gerÃ§ekleÅŸtirilen bÃ¼tÃ¼n hareketleri SIEM gibi gÃ¼venlik izleme sistemlerine besleyerek anormal bir durum olup olmadÄ±ÄŸÄ±nÄ± denetleyebilirler. Ã–rneÄŸin, normalde bir araÃ§ gÃ¼nde birkaÃ§ kez Ã§alÄ±ÅŸÄ±rken aniden yÃ¼zlerce kez Ã§alÄ±ÅŸmaya baÅŸlamÄ±ÅŸsa, bu bir kompromize iÅŸareti olabilir ve loglar sayesinde gÃ¶rÃ¼lebilir.
* **SÃ¼rÃ¼m Kilitleme ve DoÄŸrulama:** ÃœÃ§Ã¼ncÃ¼ parti MCP sunucularÄ±nÄ± uygulamanÄ±za entegre ediyorsanÄ±z, belirli gÃ¼venilir bir sÃ¼rÃ¼me kilitleyin ve bu sunucunun kodunda sonradan bir deÄŸiÅŸiklik olup olmadÄ±ÄŸÄ±nÄ± izleyin. Otomatik gÃ¼ncellemeler yerine manuel inceleme sonrasÄ± gÃ¼ncelleme yapma yaklaÅŸÄ±mÄ±nÄ± benimseyin. Bu sayede, bir araÃ§ gÃ¼ncellendiÄŸinde iÃ§ine eklenmiÅŸ olasÄ± zararlÄ± bir kod parÃ§asÄ±nÄ± fark etme ÅŸansÄ±nÄ±z olur.

YukarÄ±daki Ã¶nlemler, MCP protokolÃ¼nÃ¼n getirdiÄŸi esneklik ve gÃ¼Ã§ ile beraber gelen riskleri azaltmaya yÃ¶neliktir. Gerek bireysel geliÅŸtiriciler, gerekse MCPâ€™yi altyapÄ±larÄ±nda kullanmayÄ± planlayan kurumlar, **â€œgÃ¼venliÄŸi en baÅŸtan tasarlamaâ€** ilkesini uygulamalÄ±dÄ±r. Bu, protokolÃ¼n kendi saÄŸladÄ±ÄŸÄ± gÃ¼venlik Ã¶zellikleri kadar, kullanÄ±m ortamÄ±ndaki operasyonel gÃ¼venlik tedbirlerini de iÃ§erir.

### SonuÃ§

â€œAntopicâ€ (Anthropic) tarafÄ±ndan geliÅŸtirilen aÃ§Ä±k kaynak MCP protokolÃ¼, yapay zekÃ¢ uygulamalarÄ±nÄ±n yeteneklerini artÄ±ran yenilikÃ§i bir mimari ve standart getirmiÅŸtir. Bu Ã§alÄ±ÅŸma kapsamÄ±nda MCPâ€™nin mimari yapÄ±sÄ± ve iÅŸleyiÅŸi detaylÄ± bir ÅŸekilde incelenmiÅŸ; protokolÃ¼n LLMâ€™lerle araÃ§lar arasÄ±nda nasÄ±l bir **baÄŸlamsal kÃ¶prÃ¼** kurduÄŸu ortaya konmuÅŸtur. Elde edilen bulgular, MCPâ€™nin saÄŸladÄ±ÄŸÄ± faydalar kadar, gÃ¶z ardÄ± edilmemesi gereken gÃ¼venlik boyutunu da vurgulamaktadÄ±r. Ã–zellikle protokolÃ¼n aÃ§Ä±k kaynak doÄŸasÄ± sayesinde henÃ¼z geliÅŸtirme aÅŸamasÄ±ndayken Ã§eÅŸitli gÃ¼venlik aÃ§Ä±klarÄ± tespit edilmiÅŸ ve paylaÅŸÄ±lmÄ±ÅŸtÄ±r. Bu sayede geliÅŸtiriciler ve kullanÄ±cÄ±lar, protokolÃ¼ Ã¼retim ortamlarÄ±na taÅŸÄ±madan Ã¶nce riskleri gÃ¶rme ve Ã¶nlem alma fÄ±rsatÄ± yakalamÄ±ÅŸtÄ±r.

YapÄ±lan deÄŸerlendirmeler gÃ¶stermektedir ki MCP Ã¼zerindeki bazÄ± gÃ¼venlik aÃ§Ä±klarÄ±nÄ±n **Ã¶nceden belirlenmesi ve giderilmesi**, ileride yaÅŸanabilecek ciddi ihlallerin Ã¶nÃ¼ne geÃ§ebilecektir. Bu raporda dile getirilen potansiyel saldÄ±rÄ± vektÃ¶rleri ve gerÃ§ek dÃ¼nyada karÅŸÄ±laÅŸÄ±lan zafiyetler, protokolÃ¼n uygulanmasÄ± esnasÄ±nda nelere dikkat edilmesi gerektiÄŸine dair somut bir farkÄ±ndalÄ±k yaratÄ±r. Gerek Anthropicâ€™in resmi iyileÅŸtirmeleri, gerekse baÄŸÄ±msÄ±z araÅŸtÄ±rmacÄ±larÄ±n bulgularÄ± Ä±ÅŸÄ±ÄŸÄ±nda, MCPâ€™nin gÃ¼venlik mimarisi sÃ¼rekli evrilmektedir. DolayÄ±sÄ±yla bu Ã§alÄ±ÅŸma, hem MCP geliÅŸtiricilerine hem de protokolÃ¼ kendi sistemlerinde kullanmayÄ± dÃ¼ÅŸÃ¼nen kurumlara yÃ¶nelik proaktif bir uyarÄ± niteliÄŸindedir.

Teknik literatÃ¼re katkÄ± anlamÄ±nda, MCP protokolÃ¼nÃ¼n mimarisi ve iÅŸlevselliÄŸine dair derinlemesine bir bakÄ±ÅŸ sunulmuÅŸtur. Bu, henÃ¼z yeni sayÄ±labilecek bir standart hakkÄ±nda derli toplu bir bilgi birikimi saÄŸlamasÄ± aÃ§Ä±sÄ±ndan deÄŸerlidir. AyrÄ±ca **aÃ§Ä±k kaynak protokollerin gÃ¼venliÄŸi** konusunda genel Ã§Ä±karÄ±mlar yapma imkÃ¢nÄ± da doÄŸmuÅŸtur: ÅeffaflÄ±k ve kolektif katkÄ± sayesinde gÃ¼venlik aÃ§Ä±klarÄ±nÄ± hÄ±zla bulup dÃ¼zeltmek mÃ¼mkÃ¼n olsa da, aÃ§Ä±k ekosistemde gÃ¼venin tesis edilmesi ve sÃ¼rdÃ¼rÃ¼lmesi ayrÄ± bir Ã§aba gerektirmektedir. SonuÃ§ olarak, MCP protokolÃ¼ Ã¶zelinde elde edilen deneyimler, benzer ÅŸekilde geliÅŸtirilen diÄŸer aÃ§Ä±k kaynak projelerde de gÃ¼venlik odaklÄ± yaklaÅŸÄ±mÄ±n Ã¶nemini pekiÅŸtirmektedir.

MCP protokolÃ¼ doÄŸru uygulandÄ±ÄŸÄ±nda yapay zekÃ¢ dÃ¼nyasÄ±nda verimlilik ve yetenek artÄ±ÅŸÄ± saÄŸlayan bir araÃ§tÄ±r; ancak gÃ¼venlik prensipleri ikinci plana atÄ±lmadan, â€œÃ¶nce gÃ¼venlikâ€ yaklaÅŸÄ±mÄ±yla ele alÄ±nmalÄ±dÄ±r. Bu denge saÄŸlandÄ±ÄŸÄ±nda, MCP gibi protokoller inovasyon ile emniyeti bir arada gÃ¶tÃ¼rebilecek, hem geliÅŸtiriciler hem de kullanÄ±cÄ±lar iÃ§in bÃ¼yÃ¼k kazanÄ±mlar sunacaktÄ±r.

### Kaynaklar

* Anthropic â€” Model Context Protocol (MCP) GitHub projesi ve resmi belgeler
* GitHub Docs â€” Model Context Protocol (MCP) hakkÄ±nda dokÃ¼mantasyon
* BaÄŸÄ±msÄ±z gÃ¼venlik raporlarÄ± ve analizler (Ã¶rnek gÃ¼venlik araÅŸtÄ±rma raporlarÄ±, CVE bildirileri, proje yamalarÄ±)

---

## Ek A: LiteratÃ¼r

### Akademik Makaleler

- **Konu BaÅŸlÄ±ÄŸÄ±:** Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions
  **Kaynak/Kurum & Tarih:** arXiv, 2025-03
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2503.23278](https://arxiv.org/abs/2503.23278)
  **TÃ¼rkÃ§e Ã–zet:** MCPâ€™nin mimari ve gÃ¼venlik boyutlarÄ±nÄ± inceleyen Ã§alÄ±ÅŸma, dÃ¶rt evre ve 16 faaliyet adÄ±mÄ±ndan oluÅŸan bir yaÅŸam dÃ¶ngÃ¼sÃ¼ modeli sunar. 16 senaryoluk bir tehdit taksonomisi oluÅŸturur ve MCPâ€™nin mevcut endÃ¼stri benimsenmesini deÄŸerlendirir. ProtokolÃ¼n gÃ¼Ã§lÃ¼ yÃ¶nleri ile yaygÄ±n kullanÄ±mÄ±nÄ± sÄ±nÄ±rlayan eksikler belirlenir ve gelecekteki araÅŸtÄ±rma yÃ¶nleri tanÄ±mlanÄ±r.

- **Konu BaÅŸlÄ±ÄŸÄ±:** MCP-Universe: Benchmarking Large Language Models with Real-World Model Context Protocol Servers
  **Kaynak/Kurum & Tarih:** arXiv, 2025-08
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2508.14704](https://arxiv.org/abs/2508.14704)
  **TÃ¼rkÃ§e Ã–zet:** GerÃ§ek MCP sunucularÄ±yla etkileÅŸimli gÃ¶revlerden oluÅŸan *MCP-Universe* adlÄ± kÄ±yaslama paketi tanÄ±tÄ±lÄ±r. GPT-5, Grok-4 ve Claude-4.0-Sonnet gibi modeller test edilmiÅŸtir. Uzun-baÄŸlam ve bilinmeyen araÃ§ sorunlarÄ± tespit edilmiÅŸtir. Ã‡alÄ±ÅŸma, MCP-tabanlÄ± deÄŸerlendirme ekosisteminin aÃ§Ä±k kaynak altyapÄ±sÄ±nÄ± saÄŸlar.

- **Konu BaÅŸlÄ±ÄŸÄ±:** Automatic Red Teaming LLM-based Agents with Model Context Protocol Tools
  **Kaynak/Kurum & Tarih:** arXiv, 2025-09
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2509.21011](https://arxiv.org/abs/2509.21011)
  **TÃ¼rkÃ§e Ã–zet:** MCP araÃ§larÄ±nÄ±n **araÃ§ zehirleme saldÄ±rÄ±larÄ±na** aÃ§Ä±k olduÄŸu belirtilir. Ã–nerilen *AutoMalTool* sistemi, LLM ajanlarÄ±nÄ± kÃ¶tÃ¼ niyetli MCP araÃ§larÄ±yla otomatik olarak test eder. Bulgular, mevcut MCP gÃ¼venlik Ã¶nlemlerinin yetersiz olduÄŸunu ve sistematik kÄ±rmÄ±zÄ± takÄ±m yaklaÅŸÄ±mÄ±na ihtiyaÃ§ duyulduÄŸunu gÃ¶sterir.

- **Konu BaÅŸlÄ±ÄŸÄ±:** Advancing Multi-Agent Systems Through Model Context Protocol
  **Kaynak/Kurum & Tarih:** arXiv, 2025-04
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2504.21030](https://arxiv.org/abs/2504.21030)
  **TÃ¼rkÃ§e Ã–zet:** Ã‡ok etmenli yapay zekÃ¢ sistemlerinde baÄŸlam paylaÅŸÄ±mÄ±nÄ± standartlaÅŸtÄ±ran MCP mimarisi aÃ§Ä±klanÄ±r. Kurumsal bilgi yÃ¶netimi ve daÄŸÄ±tÄ±k problem Ã§Ã¶zme senaryolarÄ±nda performans artÄ±ÅŸÄ± saÄŸladÄ±ÄŸÄ± gÃ¶sterilir. MCPâ€™nin koordinasyon verimliliÄŸini ve baÄŸlam farkÄ±ndalÄ±ÄŸÄ±nÄ± artÄ±rdÄ±ÄŸÄ± vurgulanÄ±r.

- **Konu BaÅŸlÄ±ÄŸÄ±:** Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers
  **Kaynak/Kurum & Tarih:** arXiv, 2025-06
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2506.13538](https://arxiv.org/abs/2506.13538)
  **TÃ¼rkÃ§e Ã–zet:** 1.899 aÃ§Ä±k kaynak MCP sunucusu incelenmiÅŸ ve sekiz gÃ¼venlik aÃ§Ä±ÄŸÄ± tespit edilmiÅŸtir. SunucularÄ±n %7,2â€™sinde genel gÃ¼venlik, %5,5â€™inde araÃ§ zehirleme riski gÃ¶rÃ¼lÃ¼r. MCPâ€™ye Ã¶zgÃ¼ zafiyet tarama teknikleri Ã¶nerilir.

- **Konu BaÅŸlÄ±ÄŸÄ±:** MCP-Guard: A Defense Framework for Model Context Protocol Integrity in LLM Applications
  **Kaynak/Kurum & Tarih:** arXiv, 2025-08
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2508.10991](https://arxiv.org/abs/2508.10991)
  **TÃ¼rkÃ§e Ã–zet:** MCP-Guard adlÄ± Ã§ok katmanlÄ± savunma mimarisi Ã¶nerilir. Statik analiz, derin Ã¶ÄŸrenme tabanlÄ± dedektÃ¶r ve LLM â€œhakemâ€ modÃ¼lÃ¼ ile tehditler %96 doÄŸrulukla tespit edilir. *MCP-AttackBench* veri seti 70 000â€™den fazla saldÄ±rÄ± Ã¶rneÄŸi iÃ§erir.

- **Konu BaÅŸlÄ±ÄŸÄ±:** A Survey of the Model Context Protocol (MCP): Standardizing Context to Enhance LLMs
  **Kaynak/Kurum & Tarih:** Preprints.org, 2025-04
  **BaÄŸlantÄ±:** [https://www.preprints.org/manuscript/202504.0245/v1](https://www.preprints.org/manuscript/202504.0245/v1)
  **TÃ¼rkÃ§e Ã–zet:** MCPâ€™nin mimarisi, istemci-sunucu modeli ve dinamik araÃ§ keÅŸfi mekanizmalarÄ± incelenir. ProtokolÃ¼n ajan sistemlerinde birlikte Ã§alÄ±ÅŸabilirliÄŸi artÄ±rdÄ±ÄŸÄ±, ancak gÃ¼venlik ve benimsenme sorunlarÄ±nÄ±n devam ettiÄŸi vurgulanÄ±r.

- **Konu BaÅŸlÄ±ÄŸÄ±:** A Survey of Agent Interoperability Protocols: MCP, ACP, A2A, and ANP
  **Kaynak/Kurum & Tarih:** arXiv, 2025-05
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2505.02279](https://arxiv.org/abs/2505.02279)
  **TÃ¼rkÃ§e Ã–zet:** MCP, ACP, A2A ve ANP protokolleri karÅŸÄ±laÅŸtÄ±rÄ±lÄ±r. MCPâ€™nin JSON-RPC tabanlÄ± gÃ¼venli araÃ§ Ã§aÄŸrÄ±sÄ± saÄŸladÄ±ÄŸÄ±; ACP ve A2Aâ€™nÄ±n mesajlaÅŸma ve gÃ¶rev devri saÄŸladÄ±ÄŸÄ± aÃ§Ä±klanÄ±r. MCPâ€™nin birlikte Ã§alÄ±ÅŸabilir sistemler iÃ§in temel adÄ±m olduÄŸu sonucuna varÄ±lÄ±r.

- **Konu BaÅŸlÄ±ÄŸÄ±:** Model Context Protocols in Adaptive Transport Systems: A Survey
  **Kaynak/Kurum & Tarih:** arXiv, 2025-08
  **BaÄŸlantÄ±:** [https://arxiv.org/abs/2508.19239](https://arxiv.org/abs/2508.19239)
  **TÃ¼rkÃ§e Ã–zet:** AkÄ±llÄ± ulaÅŸÄ±m sistemlerinde baÄŸlam paylaÅŸÄ±mÄ± iÃ§in MCPâ€™nin potansiyeli analiz edilir. MCPâ€™nin anlamsal birlikte Ã§alÄ±ÅŸabilirlik saÄŸladÄ±ÄŸÄ± ve dinamik veri alÄ±ÅŸveriÅŸinde avantaj sunduÄŸu belirtilir. GeleceÄŸin uyarlanabilir ulaÅŸÄ±m mimarilerinde MCPâ€™nin temel rol oynayabileceÄŸi Ã¶ngÃ¶rÃ¼lÃ¼r.

---

### SektÃ¶rel Raporlar ve Bloglar

- **Konu BaÅŸlÄ±ÄŸÄ±:** Introducing the Model Context Protocol
  **Kaynak/Kurum & Tarih:** Anthropic, 2024-11
  **BaÄŸlantÄ±:** [https://www.anthropic.com/news/model-context-protocol](https://www.anthropic.com/news/model-context-protocol)
  **TÃ¼rkÃ§e Ã–zet:** Anthropic, MCPâ€™yi yapay zekÃ¢ asistanlarÄ± ile veri kaynaklarÄ± arasÄ±nda gÃ¼venli baÄŸlantÄ± kuran aÃ§Ä±k standart olarak tanÄ±tmÄ±ÅŸtÄ±r. SDKâ€™lar ve Ã¶rnek MCP sunucularÄ± aÃ§Ä±k kaynak paylaÅŸÄ±lmÄ±ÅŸtÄ±r. MCP, farklÄ± sistemler arasÄ±nda baÄŸlamÄ± koruyarak veri eriÅŸimini sadeleÅŸtirir.

- **Konu BaÅŸlÄ±ÄŸÄ±:** Microsoft Build 2025 â€“ The Age of AI Agents
  **Kaynak/Kurum & Tarih:** Microsoft Official Blog, 2025-05
  **BaÄŸlantÄ±:** [https://blogs.microsoft.com/blog/2025/05/19/microsoft-build-2025-the-age-of-ai-agents-and-building-the-open-agentic-web/](https://blogs.microsoft.com/blog/2025/05/19/microsoft-build-2025-the-age-of-ai-agents-and-building-the-open-agentic-web/)
  **TÃ¼rkÃ§e Ã–zet:** Microsoft, MCPâ€™yi GitHub, Copilot Studio, Dynamics 365 ve Azure AI Foundry gibi Ã¼rÃ¼nlerde entegre etmiÅŸtir. MCP YÃ¼rÃ¼tme Komitesiâ€™ne katÄ±larak protokolÃ¼n gÃ¼venli standardizasyonunu desteklemiÅŸtir. OAuth 2.1 tabanlÄ± yeni kimlik doÄŸrulama sistemi geliÅŸtirilmiÅŸtir.

- **Konu BaÅŸlÄ±ÄŸÄ±:** Introducing the Data Commons MCP Server
  **Kaynak/Kurum & Tarih:** Google Developers Blog, 2025-09
  **BaÄŸlantÄ±:** [https://developers.googleblog.com/en/datacommonsmcp/](https://developers.googleblog.com/en/datacommonsmcp/)
  **TÃ¼rkÃ§e Ã–zet:** Google, kamu veri setlerini MCP sunucusu Ã¼zerinden AI ajanlarÄ±na aÃ§mÄ±ÅŸtÄ±r. Bu yaklaÅŸÄ±m, LLMâ€™lerin gÃ¼venilir verilere eriÅŸmesini ve halÃ¼sinasyon oranÄ±nÄ±n azalmasÄ±nÄ± saÄŸlar. Data Commons MCP sunucusu Gemini CLI ve Cloud Agent Kit ile entegre Ã§alÄ±ÅŸÄ±r.

- **Konu BaÅŸlÄ±ÄŸÄ±:** A New Frontier for Network Engineers
  **Kaynak/Kurum & Tarih:** Cisco Blogs, 2025-05
  **BaÄŸlantÄ±:** [https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network](https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network)
  **TÃ¼rkÃ§e Ã–zet:** MCP, aÄŸ mÃ¼hendisliÄŸinde AI asistanlarÄ±nÄ±n gerÃ§ek aÄŸ topolojisine uygun Ã§Ã¶zÃ¼mler Ã¼retmesini saÄŸlar. JSON formatÄ±nda baÄŸlamsal aÄŸ verisi LLMâ€™e aktarÄ±lÄ±r, bÃ¶ylece model kurumun Ã¶zgÃ¼n altyapÄ±sÄ±na uyumlu yapÄ±landÄ±rmalar Ã¼retir.

- **Konu BaÅŸlÄ±ÄŸÄ±:** What is Model Context Protocol (MCP)?
  **Kaynak/Kurum & Tarih:** IBM Think Blog, 2025-05
  **BaÄŸlantÄ±:** [https://www.ibm.com/think/topics/model-context-protocol](https://www.ibm.com/think/topics/model-context-protocol)
  **TÃ¼rkÃ§e Ã–zet:** IBM, MCPâ€™yi AI ile harici servisler arasÄ±nda evrensel baÄŸlantÄ± katmanÄ± olarak tanÄ±mlar. LLMâ€™lerin eÄŸitim verisi sÄ±nÄ±rÄ±nÄ± aÅŸarak API ve veri tabanlarÄ±na gÃ¼venli eriÅŸmesini saÄŸlar. MCP, USB-C benzeri bir â€œstandart arayÃ¼zâ€ olarak gÃ¶rÃ¼lÃ¼r.

- **Konu BaÅŸlÄ±ÄŸÄ±:** WTF is Model Context Protocol (MCP) and why should publishers care?
  **Kaynak/Kurum & Tarih:** Digiday, 2025-09
  **BaÄŸlantÄ±:** [https://digiday.com/media/wtf-is-model-context-protocol-mcp-and-why-should-publishers-care/](https://digiday.com/media/wtf-is-model-context-protocol-mcp-and-why-should-publishers-care/)
  **TÃ¼rkÃ§e Ã–zet:** YayÄ±ncÄ±lÄ±k sektÃ¶rÃ¼ iÃ§in MCPâ€™nin â€œAI Ã§aÄŸÄ±nÄ±n robots.txt dosyasÄ±â€ olabileceÄŸi vurgulanÄ±r. YayÄ±ncÄ±lar MCP sunucularÄ± Ã¼zerinden hangi iÃ§eriklerin AI ajanlarÄ±na aÃ§Ä±lacaÄŸÄ±nÄ± belirleyebilir. Bu sayede hem veri gizliliÄŸi hem gelir modelleri kontrol altÄ±na alÄ±nÄ±r.

---

### Alanlara GÃ¶re YoÄŸunluk Analizi

- **En YoÄŸun Alanlar:** Yapay zekÃ¢, bilgi teknolojileri, gÃ¼venlik
- **GeliÅŸmekte Olan Alanlar:** AÄŸ mÃ¼hendisliÄŸi, veri bilimi, dijital medya
- **Potansiyel Alanlar:** Savunma, biyoteknoloji (henÃ¼z erken aÅŸama)

MCPâ€™nin en Ã§ok AI altyapÄ±sÄ±, yazÄ±lÄ±m entegrasyonu ve gÃ¼venlik konularÄ±nda ele alÄ±ndÄ±ÄŸÄ± gÃ¶rÃ¼lÃ¼r. Cisco, Google ve IBM gibi ÅŸirketler kendi alanlarÄ±nda MCPâ€™yi uygulamaya baÅŸlamÄ±ÅŸ; akademi ise Ã¶zellikle gÃ¼venlik, standardizasyon ve Ã§ok-etmenli koordinasyon boyutlarÄ±nÄ± araÅŸtÄ±rmaktadÄ±r.

---

### Genel DeÄŸerlendirme

Model Context Protocol (MCP), 2024 sonunda tanÄ±tÄ±lmasÄ±ndan bu yana AI ajanlarÄ±nÄ±n dÄ±ÅŸ dÃ¼nyayla gÃ¼venli ve standart bir biÃ§imde iletiÅŸim kurmasÄ±nÄ± saÄŸlamÄ±ÅŸtÄ±r.
2025 itibarÄ±yla MCP, **Anthropic**, **OpenAI**, **Microsoft**, **Google**, **IBM** ve **Cisco** gibi bÃ¼yÃ¼k oyuncular tarafÄ±ndan benimsenmiÅŸ, Ã§ok sayÄ±da akademik Ã§alÄ±ÅŸma da protokolÃ¼n gÃ¼venlik ve performans yÃ¶nlerini ele almÄ±ÅŸtÄ±r.
Protokol, AI ajan ekosistemini â€œtek tip baÄŸlantÄ± standardÄ±â€ altÄ±nda birleÅŸtirirken, aynÄ± zamanda yeni gÃ¼venlik risklerini de beraberinde getirmiÅŸtir.
Akademik Ã§Ã¶zÃ¼mler (Ã¶r. MCP-Guard, MCP-AttackBench) bu riskleri azaltmaya yÃ¶neliktir.
Gelecekte MCPâ€™nin tÄ±pkÄ± **USB-C** veya **HTTP** gibi evrensel bir altyapÄ± standardÄ±na dÃ¶nÃ¼ÅŸmesi beklenmektedir; bu da yapay zekÃ¢ sistemlerinin baÄŸlam farkÄ±ndalÄ±ÄŸÄ±nÄ±, gÃ¼venliÄŸini ve birlikte Ã§alÄ±ÅŸabilirliÄŸini kÃ¶klÃ¼ biÃ§imde geliÅŸtirecektir.

---

---

## Ek B: Google Scholar ve Sentez

> Not: Bu bÃ¶lÃ¼mdeki giriÅŸ ve mimari Ã¶zetler Rapor bÃ¶lÃ¼mÃ¼yle Ã¶rtÃ¼ÅŸÃ¼r. TekrarÄ± azaltmak iÃ§in odak; makale Ã¶zetleri, tematik sentez ve ek kaynaklardÄ±r.

### Ã–nemli Akademik Makaleler

AÅŸaÄŸÄ±daki Ã¶zetler, MCPâ€™nin geliÅŸtirilmesi, uygulanmasÄ± ve **ampirik deÄŸerlendirmesine** odaklanarak, protokolÃ¼n anlaÅŸÄ±lmasÄ±nÄ± yÃ¶nlendiren Ã§ekirdek literatÃ¼rÃ¼ temsil eder.

- **Ã–zet 1:** BÃ¼yÃ¼k Dil Modelleri (LLMâ€™ler) pasif metin Ã¼reticilerinden **aktif ajanlara** evrilmektedirâ€¦ **[Kaynak: 2]**
- **Ã–zet 5:** **AraÃ§ Ã§aÄŸÄ±rma**, AI ajanlarÄ±nÄ±n gerÃ§ek dÃ¼nyayla etkileÅŸimi ve karmaÅŸÄ±k sorunlarÄ± Ã§Ã¶zmesi iÃ§in kritik bir yetenektirâ€¦ **[Kaynak: 6]**
- **Ã–zet (BulgularÄ±n Ã–zeti) 2:** MCP iÃ§in gelecekteki araÅŸtÄ±rma yÃ¶nleri; **standardizasyon**, **gÃ¼ven sÄ±nÄ±rlarÄ±** ve **sÃ¼rdÃ¼rÃ¼lebilir bÃ¼yÃ¼me**yi gÃ¼Ã§lendirmeye odaklanÄ±r. GÃ¼venlik, Ã¶lÃ§eklenebilirlik ve yÃ¶netiÅŸim sorunlarÄ± Ã¶ne Ã§Ä±kar. DaÄŸÄ±tÄ±k **sunucu yÃ¶netimi**, merkezi bir uyumluluk otoritesinin yokluÄŸunda **yama tutarsÄ±zlÄ±klarÄ±** ve **yapÄ±landÄ±rma sapmalarÄ±**na yol aÃ§abilirâ€¦ **[Kaynak: 2]**
- **Ã–zet 6:** LLMâ€™lerin yetenekleri, Ã§eÅŸitli veri kaynaklarÄ± veya API sonuÃ§larÄ±nÄ± entegre etmek iÃ§in **iÅŸlev Ã§aÄŸrÄ±larÄ±** ile geniÅŸletilirâ€¦ **[Kaynak: 6]**
- **Ã–zet (Ekonomik AraÅŸtÄ±rma UygulamasÄ±) 4:** Bu makale; planlama, araÃ§ kullanÄ±mÄ± vb. iÅŸlevleri yerine getiren otonom **LLM tabanlÄ± sistemleri (AI ajanlarÄ±nÄ±)** anlaÅŸÄ±lÄ±r kÄ±larâ€¦ **[Kaynak: 4]**

---

### AraÅŸtÄ±rmanÄ±n Tematik Ã–zeti

### Temel TanÄ±m ve Mimari

#### Mimari Temeller: Ä°stemci-Sunucu Modeli ve Protokol TasarÄ±mÄ±
MCP, temel bir **istemciâ€“sunucu** mimarisi kurar:
- **MCP Ä°stemcileri (ajan/uygulama):** Sunuculara baÄŸlanÄ±r, **yetkinlikleri keÅŸfeder**, Ã§aÄŸÄ±rÄ±r ve sonuÃ§larÄ± LLM baÄŸlamÄ±na entegre eder. [4]
- **MCP SunucularÄ±:** Harici veri kaynaklarÄ±yla **gerÃ§ek API etkileÅŸimlerini yÃ¼rÃ¼tÃ¼r**, kimlik doÄŸrulama ve yÃ¼rÃ¼tmeyi yÃ¶netir. [4]

Protokol, **JSON-RPC 2.0** standardÄ±na dayanÄ±r; bu seÃ§im **gÃ¼Ã§lÃ¼ tipleme**, aÃ§Ä±k istek/yanÄ±t yaÅŸam dÃ¶ngÃ¼sÃ¼, **izin katmanlarÄ±** ve istemci-sunucu **akÄ±ÅŸ mekanizmalarÄ±** gibi gÃ¼venlik-Ã¶ncelikli Ã¶zellikleri kolaylaÅŸtÄ±rÄ±r. [3]

#### Temel BileÅŸenler ve Åema BaÄŸÄ±mlÄ±lÄ±ÄŸÄ±
MCP, LLM tarafÄ±ndan dinamik keÅŸif ve Ã§aÄŸÄ±rma iÃ§in **harici araÃ§larÄ±n ÅŸema ile tanÄ±mlanmasÄ±na** dayanÄ±r. [1] Akademik literatÃ¼r, bu ÅŸemalar iÃ§in **OpenAPI 2.0/3.0** kullanÄ±lmasÄ±nÄ±n etkili olduÄŸunu doÄŸrular. [1]

**LLM**, aracÄ± doÄŸru entegre etmek iÃ§in **parametreler/girdiler/Ã§Ä±ktÄ±lar**Ä±n ayrÄ±ntÄ±lÄ± tanÄ±mÄ±na ihtiyaÃ§ duyar; **MCP sunucusu** bu tanÄ±mlarÄ± kaydeder ve LLMâ€™nin **dosya sistemleri, web tarayÄ±cÄ±larÄ±, finansal veriler** gibi Ã¶zelliklere eriÅŸmesini saÄŸlar. [6]

**Tablo 3.1 â€“ MCP Mimari BileÅŸenleri ve Ä°ÅŸlevleri**

| BileÅŸen                     | RolÃ¼                                                                 | Temel Ä°ÅŸlev                                  | Standart/Protokol  | Anahtar Ã–zellik/KÄ±sÄ±tlama                                                                 |
|----------------------------|----------------------------------------------------------------------|----------------------------------------------|--------------------|-------------------------------------------------------------------------------------------|
| **MCP Ä°stemcisi (Ajan)**   | AraÃ§larÄ± keÅŸfeder/Ã§aÄŸÄ±rÄ±r; Ã§Ä±ktÄ±larÄ±nÄ± LLM baÄŸlamÄ±na entegre eder    | Planlama ve baÄŸlam yÃ¶netimi                  | JSON-RPC 2.0       | BaÄŸlam penceresi sÄ±nÄ±rlÄ±dÄ±r; **araÃ§ numaralandÄ±rma** belirteÃ§ uzunluÄŸunu yÃ¶netmelidir. [6] |
| **MCP Sunucusu**           | DÄ±ÅŸ yetenekleri ortaya Ã§Ä±karÄ±r; yÃ¼rÃ¼tme ve kimlik doÄŸrulamayÄ± yÃ¶netir | Kaynak/araÃ§ barÄ±ndÄ±rma                       | OpenAPI-tÃ¼revi     | YÃ¼ksek kaliteli ÅŸema gerekir; baÅŸlangÄ±Ã§ta **manuel iskele** darboÄŸazlarÄ± gÃ¶rÃ¼lebilir. [1] |
| **Protokol TasarÄ±mÄ±**      | StandartlaÅŸtÄ±rÄ±lmÄ±ÅŸ araÃ§ tanÄ±mÄ± ve etkileÅŸimi                         | Birlikte Ã§alÄ±ÅŸabilir arayÃ¼z                   | JSON-RPC 2.0       | ModÃ¼lerlik, izinler ve **Ã¶lÃ§eklenebilir optimizasyon** (Ã¶nbellek, toplu iÅŸleme). [3]      |

### Uygulama, Ã–lÃ§eklenebilirlik ve Benimseme Dinamikleri

#### Manuel Sunucu GeliÅŸtirme DarboÄŸazÄ±nÄ±n Nicelendirilmesi
MCPâ€™nin yayÄ±nÄ±ndan sonraki 6 ayda oluÅŸturulan **22.000+ MCP etiketli repo**nun analizinde, **%5â€™ten azÄ±nÄ±n** iÅŸlevsel sunucu uygulamalarÄ± iÃ§erdiÄŸi raporlanmÄ±ÅŸtÄ±r. [1] BirÃ§ok proje **tek bakÄ±mcÄ±**, **elle ÅŸema/kimlik doÄŸrulama** gibi tekrar eden Ã§abalar iÃ§erir. [1]

#### Otomasyon: AutoMCP ve OpenAPI'nin RolÃ¼
**AutoMCP derleyici**, OpenAPI sÃ¶zleÅŸmelerinden **tam MCP sunucularÄ±** Ã¼retebilmektedir. 50 gerÃ§ek dÃ¼nya APIâ€™sinde (10+ alan, 5.066 uÃ§ nokta) yapÄ±lan deÄŸerlendirmede:
- 1.023 araÃ§ Ã§aÄŸrÄ±sÄ±ndan **%76,5**â€™i ilk denemede baÅŸarÄ±lÄ±,
- KÃ¼Ã§Ã¼k dÃ¼zeltmeler (API baÅŸÄ±na ~**19 satÄ±r** deÄŸiÅŸiklik) sonrasÄ± baÅŸarÄ± **%99,9**â€™a yÃ¼kselmiÅŸtir. [1]

#### Yeni Benimseme Engeli: Spesifikasyon Kalitesi
Otomasyonun baÅŸarÄ±sÄ±, zorluÄŸun artÄ±k **kod Ã¼retimi** deÄŸil, **OpenAPI sÃ¶zleÅŸme kalitesi** olduÄŸunu gÃ¶sterir. KuruluÅŸlar **API yÃ¶netiÅŸimine** ve **dokÃ¼mantasyon doÄŸruluÄŸuna** Ã¶ncelik vermelidir. [1]

### Uygulama AlanlarÄ± ve Ã–rnekler

#### Genel Ajan Ä°ÅŸ AkÄ±ÅŸlarÄ± ve Ekosistem BÃ¼yÃ¼mesi
Binlerce baÄŸÄ±msÄ±z MCP sunucusu; **GitHub, Slack** gibi hizmetlere eriÅŸim saÄŸlar. **MCPToolBench++**, 4.000+ MCP sunucusundan oluÅŸan pazarda veri analizi, dosya iÅŸlemleri, finansal hesaplama vb. geniÅŸ uygulama alanÄ±nÄ± doÄŸrular. [6]

#### Ã–zel Alan: Ekonomik ve Kurumsal AraÅŸtÄ±rma
MCP, ajanlarÄ±n **kurumsal veritabanlarÄ±na** (Ã¶r. merkez bankasÄ±/Ã¶zel veri) baÄŸlanÄ±p **sÃ¼rdÃ¼rÃ¼lebilir baÄŸlantÄ±lar** kurmasÄ±nÄ± saÄŸlar; literatÃ¼r incelemeleri, ekonometrik kodlama ve **Ã¶zel veri analizi** gibi **Ã¶zerk araÅŸtÄ±rma iÅŸ akÄ±ÅŸlarÄ±** mÃ¼mkÃ¼n olur. [4]

### Performans: KarÅŸÄ±laÅŸtÄ±rma ve Analiz

#### Son Teknoloji Benchmark'lar
- **LiveMCP-101:** 101 gerÃ§ek dÃ¼nya sorgusu, Ã§ok-adÄ±mlÄ± planlar ve koordinasyon gerektirir. [5]
- **MCPToolBench++:** FarklÄ± yanÄ±t biÃ§imleri ve araÃ§ baÅŸarÄ± oranÄ± deÄŸiÅŸkenliÄŸini adresler; Ã§ok alanlÄ± Ã§erÃ§eve sunar. [6]

#### Bulgular: AraÃ§ Koordinasyon EksikliÄŸi
En geliÅŸmiÅŸ LLMâ€™ler bile **karmaÅŸÄ±k Ã§ok-adÄ±mlÄ±** gÃ¶revlerde **%60â€™Ä±n altÄ±nda** baÅŸarÄ± gÃ¶stermiÅŸtir. [5] MCP, eriÅŸimi standartlaÅŸtÄ±rsa da **gÃ¼venilir yÃ¼rÃ¼tme** iÃ§in yeterli deÄŸildir; sÄ±nÄ±rlama **planlama/koordinasyon** yeteneklerindedir.

#### ArÄ±za ModlarÄ± ve Kaynak KÄ±sÄ±tlarÄ±

**Tablo 3.2 â€“ MCP Etkin Ajan YÃ¼rÃ¼tmede GÃ¶zlemlenen ArÄ±za ModlarÄ± (LiveMCP-101)**

| Hata Kategorisi        | Ã–rnek ArÄ±za Modu                          | AÃ§Ä±klama                                                                                 | Kaynak |
|------------------------|--------------------------------------------|------------------------------------------------------------------------------------------|--------|
| AraÃ§ Koordinasyonu     | **DÃ¼ÅŸÃ¼k BaÅŸarÄ±**                           | Ã‡ok-adÄ±mlÄ± eylemlerde baÅŸarÄ±sÄ±zlÄ±k; karmaÅŸÄ±k koordinasyon gereksinimleri                | [5]    |
| AraÃ§ Koordinasyonu     | **AÅŸÄ±rÄ± Ã¶zgÃ¼venli iÃ§ Ã§Ã¶zÃ¼m**               | Ajan, temelli MCP aracÄ±nÄ± atlayÄ±p iÃ§ muhakemeye gÃ¼venir; halÃ¼sinasyon/erken bitiÅŸ       | [5]    |
| AraÃ§ Koordinasyonu     | **Gereksinimi gÃ¶z ardÄ±**                   | AÃ§Ä±k gereksinim atlanÄ±r; ilgili araÃ§ seÃ§ilmez                                            | [5]    |
| Uygulama               | **Parametre hatalarÄ±**                     | Girdi parametreleri yanlÄ±ÅŸ biÃ§imlenir/atlanÄ±r                                            | [5]    |
| Ã–lÃ§eklenebilirlik/BaÄŸlam| **Token verimsizlikleri/sÄ±nÄ±rlarÄ±**        | Åema envanteri baÄŸlam penceresini tÃ¼ketir; planlama/akÄ±l yÃ¼rÃ¼tme iÃ§in alan daralÄ±r      | [5,6]  |

---

### SonuÃ§ ve AraÅŸtÄ±rma BoÅŸluklarÄ±

### Mevcut Durumun Ã–zeti
MCP, **araÃ§ etkileÅŸimini standartlaÅŸtÄ±rma** hedefini bÃ¼yÃ¼k Ã¶lÃ§Ã¼de baÅŸarmÄ±ÅŸ; **OpenAPI tabanlÄ±** otomatik sunucu oluÅŸturma ile geliÅŸtirici engellerini azaltmÄ±ÅŸtÄ±r. [1] Ekosistem bÃ¼yÃ¼mÃ¼ÅŸ; ancak iki kritik alan aÃ§Ä±k kalmÄ±ÅŸtÄ±r:
1) **Ajans gÃ¼venilirliÄŸi** (Ã§ok-adÄ±mlÄ± gÃ¶revlerde dÃ¼ÅŸÃ¼k baÅŸarÄ±),
2) **Ekosistem yÃ¶netiÅŸimi** (gÃ¼venlik/uyumluluk). [2]

### Ã‡Ã¶zÃ¼lmemiÅŸ Zorluklar ve Gelecek YÃ¶nelimler

#### GÃ¼venlik AÃ§Ä±klarÄ± ve GÃ¼ven SÄ±nÄ±rlarÄ±
DaÄŸÄ±tÄ±k sunucu yÃ¶netimi, merkezi uyumluluk yokluÄŸunda **heterojen uygulamalar** ve **yama tutarsÄ±zlÄ±klarÄ±**na yol aÃ§ar. **Zorunlu konfigÃ¼rasyon doÄŸrulamasÄ±**, **otomatik sÃ¼rÃ¼m kontrolÃ¼** ve **bÃ¼tÃ¼nlÃ¼k denetimi** gibi teknik yÃ¶netiÅŸim Ã§Ã¶zÃ¼mleri Ã¶ncelik olmalÄ±dÄ±r. [2]

#### Ã–lÃ§eklenebilirlik, ParÃ§alanma ve YÃ¶netiÅŸim
BaÄŸlam penceresi kÄ±sÄ±tÄ±, **araÃ§ envanteri** â†” **akÄ±l yÃ¼rÃ¼tme derinliÄŸi** arasÄ±nda Ã¶dÃ¼nleÅŸim yaratÄ±r. **Dinamik, baÄŸlamsal araÃ§ keÅŸfi** ve **ÅŸema sÄ±kÄ±ÅŸtÄ±rma** araÅŸtÄ±rmalarÄ± Ã¶nceliklidir. [6] DÃ¼ÅŸÃ¼k gÃ¼venilirlik, yÃ¼ksek riskli kurumsal alanlarda etik, gÃ¼venlik ve yasal sonuÃ§larÄ± bÃ¼yÃ¼tÃ¼r; **adalet**, **veri sÄ±zÄ±ntÄ±sÄ± savunmasÄ±** ve **hesap verebilirlik** odaklÄ± yÃ¶netiÅŸim ÅŸarttÄ±r. [2,4]

### Kaynaklar
1. **Making REST APIs Agent-Ready: From OpenAPI to MCP** â€“ arXiv (13 Eki 2025) â†’ https://arxiv.org/abs/2507.16044
2. **Model BaÄŸlam ProtokolÃ¼ (MCP): Manzara, GÃ¼venlik Tehditleriâ€¦** â€“ arXiv (13 Eki 2025) â†’ https://arxiv.org/pdf/2503.23278
3. **Model BaÄŸlam ProtokolÃ¼ (MCP) Nedir | NasÄ±l Ã‡alÄ±ÅŸÄ±r** â€“ Kodexo Labs (13 Eki 2025) â†’ https://kodexolabs.com/what-is-model-context-protocol-mcp/
4. **AI Agents for Economic Research** â€“ NBER Working Paper (13 Eki 2025) â†’ https://www.nber.org/system/files/working_papers/w34202/w34202.pdf
5. **LiveMCP-101: Stress-Testing MCP-Enabled Systems** â€“ arXiv (13 Eki 2025) â†’ https://arxiv.org/abs/2508.15760
6. **MCPToolBench++: A Large-Scale AI Agent MCP Benchmark** â€“ arXiv (13 Eki 2025) â†’ https://arxiv.org/abs/2508.07575

---

# Model BaÄŸlam ProtokolÃ¼ (MCP): LLM Entegrasyonu, Ajans Sistemleri ve AraÃ§ KullanÄ±mÄ± Standardizasyonunda RolÃ¼nÃ¼n Uzman Analizi

### Otonom Yapay ZekÃ¢ iÃ§in Temel Katman Olarak MCP
LLMâ€™lerin harici kaynaklar ve araÃ§larla **dinamik arayÃ¼z** oluÅŸturmasÄ± iÃ§in standart, gÃ¼venilir bir yÃ¶ntem eksikti. **MCP**, AI modelleri ile harici kaynak/araÃ§lar arasÄ±nda **birleÅŸik, Ã§ift yÃ¶nlÃ¼ iletiÅŸim katmanÄ±** tanÄ±mlayarak bu boÅŸluÄŸu doldurur. MCP, **parÃ§alanmayÄ±** azaltÄ±r ve **pasif iÅŸlev aÃ§Ä±klamalarÄ±nÄ±** **aktif baÄŸlam kaynaklarÄ±na** dÃ¶nÃ¼ÅŸtÃ¼rÃ¼r. 2025â€™teki yayÄ±n kÃ¼meleri, MCPâ€™nin **acil bir endÃ¼stri tepkisi** olarak olgunlaÅŸtÄ±ÄŸÄ±nÄ± gÃ¶sterir. [2]

### Mimari Gereklilik: DaÄŸÄ±tÄ±m Modelleri ve GeliÅŸmiÅŸ Sistem Entegrasyonu

#### FaaS ile BarÄ±ndÄ±rÄ±lan MCP Hizmetleri
**AgentX** Ã§alÄ±ÅŸmasÄ±, MCP sunucularÄ±nÄ±n **FaaS** Ã¼zerinde barÄ±ndÄ±rÄ±lmasÄ±nÄ±n baÅŸarÄ±, gecikme ve maliyet aÃ§Ä±sÄ±ndan avantajlarÄ±nÄ± gÃ¶sterir; **patlama** tarzÄ± kullanÄ±m profilleriyle doÄŸal uyum saÄŸlar. [9]

#### MoE Mimarilerinde MCP
**Uzman KarÄ±ÅŸÄ±mÄ± (MoE)** senaryolarÄ±nda MCP, **MITRE ATT&CK, MISP, CVE** gibi tehdit istihbaratÄ± kaynaklarÄ±nÄ± baÄŸlayarak **semantik baÄŸlam farkÄ±ndalÄ±ÄŸÄ±** saÄŸlar; endÃ¼striyel ortamlarda uyarlanabilir karar vermeyi gÃ¼Ã§lendirir.

**Tablo 1 â€“ Temel MCP AraÅŸtÄ±rmalarÄ± (2025 KÃ¼mesi): Zaman Ã‡izelgesi ve Odak**

| Ã‡alÄ±ÅŸma (KÄ±saltma)                                   | YayÄ±n (YaklaÅŸÄ±k) | Birincil Tema            | Ana Mimari KavramÄ±                              |
|------------------------------------------------------|------------------|--------------------------|--------------------------------------------------|
| MCP â€“ Manzara & GÃ¼venlik (Hou ve ark.)               | 2025-03          | TanÄ±m & GÃ¼venlik         | Tam Sunucu YaÅŸam DÃ¶ngÃ¼sÃ¼; Tehdit SÄ±nÄ±flandÄ±rmasÄ± |
| MCPmed â€“ Biyoinformatik Ã‡aÄŸrÄ±sÄ±                      | 2025-07          | Alan UzmanlÄ±ÄŸÄ±           | FAIR-uyumlu makine-okunur katman                 |
| Help or Hindrance? (MCPGAUGE)                        | 2025-08          | Ampirik DeÄŸerlendirme    | Proaktiflik/Genel Gider Analizi                  |
| AgentX â€“ FaaS Ã¼zerinde MCP                            | 2025-09          | Ä°ÅŸ AkÄ±ÅŸÄ± DÃ¼zenleme       | FaaS-barÄ±ndÄ±rmalÄ± MCP Hizmetleri                 |

### YÃ¶rÃ¼nge: Proaktif GÃ¼venlik TasarÄ±mÄ± ve Tehdit SÄ±nÄ±flandÄ±rmasÄ±
MCP ile **Ã§ift yÃ¶nlÃ¼ iletiÅŸim**, yeni saldÄ±rÄ± yÃ¼zeyleri getirir. LiteratÃ¼r, 4 saldÄ±rgan tÃ¼rÃ¼ ve **16 tehdit senaryosu** ile kapsamlÄ± bir **tehdit modeli** sunar ve yaÅŸam dÃ¶ngÃ¼sÃ¼-Ã¶zgÃ¼ **uygulanabilir Ã¶nlemler** Ã¶nerir. [2]

### YÃ¶rÃ¼nge: Performans DoÄŸrulama ve AraÃ§ KullanÄ±mÄ±nÄ±n Engeli
**MCPGAUGE**, 160 prompt/25 veri seti/â‰ˆ20k API Ã§aÄŸrÄ±sÄ± ile 6 ticari LLM ve 30 MCP araÃ§ paketinde 4 boyutta Ã¶lÃ§Ã¼m yapar: **Proaktiflik, Uyum, Etkinlik, Genel Gider**. Bulgular, MCPâ€™nin mimari yararlarÄ±nÄ±n **otomatik performans artÄ±ÅŸÄ±** garantilemediÄŸini; **uyum/proaktiflik** dÃ¼ÅŸÃ¼klÃ¼ÄŸÃ¼ ve **ek yÃ¼k** sorunlarÄ±nÄ±n kritik olduÄŸunu gÃ¶sterir. (LLM eÄŸitimi ve ince ayarlarÄ±nÄ±n MCP-uyumlu optimizasyonu Ã¶nerilir.)

**Tablo 2 â€“ MCP Entegrasyonu: Avantajlar, Riskler ve Performans BoyutlarÄ±**

| Kategori     | GÃ¶zlemlenen Fayda                                           | Risk/SÄ±nÄ±rlama                                  | Ä°lgili Boyut     |
|--------------|--------------------------------------------------------------|--------------------------------------------------|------------------|
| Mimari       | BirleÅŸik/dinamik araÃ§ keÅŸfi; FaaS Ã¶lÃ§eklenebilirliÄŸi; MoE    | Tam yaÅŸam dÃ¶ngÃ¼sÃ¼ yÃ¶netimi (16 faaliyet)         | **Etkinlik**     |
| Ä°ÅŸlevsel     | Anlamsal baÄŸlam; dinamik veri yorumlama; Ã¶zerklik            | Uyum eksikliÄŸi; dÃ¼ÅŸÃ¼k proaktiflik                | **Proaktiflik/ Uyumluluk** |
| Operasyonel  | Tekrarlanabilirlik; mÃ¼dahalesiz varlÄ±k yÃ¶netimi               | Hesaplama maliyeti ve gecikme                    | **Genel Gider**  |
| GÃ¼venlik     | DÄ±ÅŸ tehdit istihbaratÄ± entegrasyonu                           | 16 tehdit senaryosuna maruziyet                  | â€”                |

### YÃ¶rÃ¼nge: GeliÅŸmiÅŸ Ajan Ä°ÅŸ AkÄ±ÅŸÄ± DÃ¼zenleme
**AgentX** modeli (sahne tasarÄ±mcÄ±sÄ±, planlayÄ±cÄ±, yÃ¼rÃ¼tÃ¼cÃ¼) ile **FaaS-barÄ±ndÄ±rmalÄ± MCP** araÃ§larÄ±; pratik uygulamalarda **baÅŸarÄ±, gecikme, maliyet** aÃ§Ä±sÄ±ndan avantaj saÄŸlar. **GenAI + MCP + Applied ML** birlikteliÄŸi, saÄŸlÄ±k/finans/robotik gibi alanlarda **baÄŸlam duyarlÄ± otonomi** iÃ§in temel sunar. [6,9]

### YÃ¶rÃ¼nge: Alanlar ArasÄ± UzmanlaÅŸma ve Standardizasyon

#### MCPmed: Biyomedikal AraÅŸtÄ±rmada FAIR Ä°lkeleri
GEO, STRING, UCSC Cell Browser gibi **insan-merkezli** web sunucularÄ±nÄ±n **LLM-okunabilirliÄŸini** MCP ile artÄ±rma Ã§aÄŸrÄ±sÄ±; **yapÄ±landÄ±rÄ±lmÄ±ÅŸ, makine-iÅŸlenebilir katman** ile otomasyon/tekrarlanabilirlik/birlikte Ã§alÄ±ÅŸabilirlik kazancÄ±. [7]

#### Kritik AltyapÄ± VarlÄ±k KeÅŸfi
ICSâ€™de **deterministik araÃ§larÄ±n** sÄ±nÄ±rlamalarÄ±na karÅŸÄ±; MoE + MCP ile **tehdit istihbaratÄ±** (MITRE ATT&CK, MISP, CVE) entegrasyonu ve **baÄŸlam zenginleÅŸtirme** Ã¼zerinden uyarlanabilir keÅŸif ve gÃ¼venlik duruÅŸu gÃ¼Ã§lendirme. [11]

**Tablo 3 â€“ Alan Spesifik Zorluklarda MCPâ€™nin RolÃ¼**

| Etki AlanÄ±              | MCP Ã–ncesi SÄ±nÄ±rlama                                   | MCP Ã‡Ã¶zÃ¼mÃ¼/Ã‡erÃ§evesi                               | Temel MCP Ä°ÅŸlevi                              |
|-------------------------|---------------------------------------------------------|-----------------------------------------------------|-----------------------------------------------|
| Biyoinformatik/AraÅŸtÄ±rma| LLM-okunabilirliÄŸini sÄ±nÄ±rlayan insan-merkezli sunucular| **MCPmed**; hafif â€œbreadcrumbâ€ ve ÅŸablonlar         | FAIR uyumlu **makine-iÅŸlenebilir eriÅŸim** [7] |
| Kritik AltyapÄ± (ICS)    | BaÄŸlamsal muhakemeden yoksun deterministik araÃ§lar     | MoE + MCP ile tehdit istihbaratÄ± entegrasyonu       | **BaÄŸlam enjeksiyonu** (MISP/CVE baÄŸlama)     |

### Google Scholar Ã–zet Koleksiyonu (Markdown)

- **Model BaÄŸlam ProtokolÃ¼ (MCP): Genel Durum, GÃ¼venlik Tehditleri ve Gelecek YÃ¶nelimler** â€” *Hou ve ark.*
  **Ã–zet:** MCP, birleÅŸik, Ã§ift yÃ¶nlÃ¼â€¦ **[Kaynak: 2]**

- **AgentX: FaaS-BarÄ±ndÄ±rÄ±lan MCP Hizmetleri ile SaÄŸlam Ajan Ä°ÅŸ AkÄ±ÅŸlarÄ±** â€” *Tokal ve ark.*
  **Ã–zet:** GenAI Ã§eÅŸitli alanlarÄ± dÃ¶nÃ¼ÅŸtÃ¼rmÃ¼ÅŸtÃ¼râ€¦ **[Kaynak: 9]**

- **Help or Hindrance? Rethinking LLMs Empowered with MCP** â€” *Song ve ark.*
  **Ã–zet:** MCP, LLMâ€™lerin eriÅŸimini saÄŸlarâ€¦ **[Kaynak: 10]**

- **MCPmed: LLM-OdaklÄ± KeÅŸif iÃ§in MCP-Destekli Biyoinformatik Web Hizmetleri Ã‡aÄŸrÄ±sÄ±** â€” *Flotho ve ark.*
  **Ã–zet:** Biyoinformatik web sunucularÄ±â€¦ **[Kaynak: 7]**

- **Integrating GenAI & MCP with Applied ML for Advanced Agentic AI Systems** â€” *Bhandarwar*
  **Ã–zet:** GenAI, MCP ve UygulamalÄ± MLâ€¦ **[Kaynak: 12]**

### Sentez ve Gelecekteki Standardizasyon ZorluklarÄ±

MCP, birinci nesil ajan sistemlerinin **Ã¶lÃ§eklenebilirlik** ve **baÄŸlam yÃ¶netimi** sÄ±nÄ±rlarÄ±nÄ± aÅŸmak iÃ§in gerekli mimari olgunluÄŸu saÄŸlar; **otomasyon** (AutoMCP), **FaaS daÄŸÄ±tÄ±mÄ±** (AgentX) ve **alan-Ã¶zgÃ¼ adaptasyonlar** (MCPmed) bunu destekler.
KalÄ±cÄ± iki zorunluluk:
- **GÃ¼venlik Riski YÃ¶netimi:** 16 tehdit senaryosu ve 4 saldÄ±rgan tÃ¼rÃ¼; yaÅŸam dÃ¶ngÃ¼sÃ¼-Ã¶zgÃ¼ Ã¶nlemler, **politika yÃ¶netimi** ve **denetim izleri** ÅŸart. [2]
- **Verimlilik ve Model UyumluluÄŸu:** MCPGAUGE, **uyum/proaktiflik** ve **ek yÃ¼k** sorunlarÄ±na iÅŸaret eder; **MCP-uyumlu eÄŸitim** ve **etkileÅŸim maliyeti azaltÄ±mÄ±** Ã¶nceliklidir. [10]

**SÃ¼rdÃ¼rÃ¼lebilir BÃ¼yÃ¼me:** MCPmed ve ICS Ã¶rnekleri, protokolÃ¼n **uyarlanabilirliÄŸini** gÃ¶sterir. Gelecek Ã§alÄ±ÅŸmalar, **standardizasyonun gÃ¼Ã§lendirilmesi**, **gÃ¼ven sÄ±nÄ±rlarÄ±nÄ±n iyileÅŸtirilmesi** ve **LLM performansÄ±nÄ±n MCPâ€™ye optimize edilmesi**ne odaklanmalÄ±dÄ±r.

### Ek Kaynaklar

7. **MCPmed: A Call for MCP-Enabled Bioinformatics Web Services** â€“ arXiv â†’ https://arxiv.org/abs/2507.08055
8. **MCPmed (HTML sÃ¼rÃ¼m)** â€“ arXiv â†’ https://arxiv.org/html/2507.08055v1
9. **AgentX: Toward Robust Agent Workflow with FaaS-Hosted MCP Services** â€“ arXiv â†’ https://arxiv.org/abs/2509.07595
10. **Help or Hindrance? Rethinking LLMs Empowered with MCP** â€“ arXiv â†’ https://arxiv.org/abs/2508.12566
11. **Asset Discovery in Critical Infrastructures: An LLM-Based Approach** â€“ MDPI â†’ https://www.mdpi.com/2079-9292/14/16/3267
12. **Integrating Generative AI & MCP with Applied MLâ€¦** â€“ ResearchGate â†’ (PDF baÄŸlantÄ±sÄ± kullanÄ±cÄ± paylaÅŸÄ±mlÄ±)

> **Not:** BazÄ± baÄŸlantÄ±lar Ã¼Ã§Ã¼ncÃ¼ taraf barÄ±ndÄ±rÄ±cÄ±lar Ã¼zerinde olabilir ve eriÅŸim kÄ±sÄ±tlarÄ±/URL deÄŸiÅŸimleri iÃ§erebilir.

---

## Ek C: GÃ¼ncel Olaylar

### MCP'de AraÃ§ Zehirleme SaldÄ±rÄ±larÄ± (Tool Poisoning Attacks)
MCP sunucularÄ±nda araÃ§ tanÄ±mlarÄ±na gizli zararlÄ± talimatlar enjekte edilerek AI asistanlarÄ±nÄ±n manipÃ¼le edilmesi, SSH anahtarlarÄ± ve API anahtarlarÄ± gibi hassas verilerin sÄ±zdÄ±rÄ±lmasÄ±na yol aÃ§an kritik bir tehdit. SaldÄ±rÄ±lar, kullanÄ±cÄ± onayÄ± altÄ±nda gizli eylemler gerÃ§ekleÅŸtirerek veri dÄ±ÅŸa aktarÄ±mÄ± veya yetkisiz eriÅŸim saÄŸlÄ±yor. GeniÅŸ Ã§apta tartÄ±ÅŸÄ±lan bu saldÄ±rÄ± tÃ¼rÃ¼, MCP'nin tedarik zinciri risklerini vurguluyor.

Ä°lgili X postlarÄ±:
- https://x.com/Graham_dePenros/status/1976216281033408741
- https://x.com/lbeurerkellner/status/1907075048118059101
- https://x.com/akshay_pachaar/status/1947246782221816087
- https://x.com/akshay_pachaar/status/1946926773918429249
- https://x.com/Graham_dePenros/status/1976252021645959302
- https://x.com/OpenCodeMission/status/1976251957108248856
- https://x.com/OpenCodeMission/status/1976245247685316721
- https://x.com/theagentangle/status/1976018568413405335

### MCP Ãœst 25 Zafiyet Raporu (Top 25 Vulnerabilities Report)
MCP'de tespit edilen 25 kritik zafiyetin 18'i kolay sÃ¶mÃ¼rÃ¼lebilir olarak sÄ±nÄ±flandÄ±rÄ±lÄ±yor; prompt enjeksiyonu, komut enjeksiyonu ve eksik kimlik doÄŸrulamasÄ± gibi temel gÃ¼venlik hatalarÄ±, web geliÅŸtirme standartlarÄ±nÄ±n gerisinde kalÄ±yor. Rapor, AI ajanlarÄ±nÄ±n veritabanÄ± ve dosya sistemi eriÅŸimlerinde input doÄŸrulama eksikliÄŸini vurgulayarak Ã¼retim ortamlarÄ±nda acil gÃ¼venlik disiplini gerekliliÄŸini belirtiyor.

Ä°lgili X postlarÄ±:
- https://x.com/rryssf_/status/1970524674439422444
- https://x.com/kakarot_ai/status/1975599529681690820
- https://x.com/lbeurerkellner/status/1907075048118059101 (baÄŸlantÄ±lÄ± tartÄ±ÅŸma)

### AÃ§Ä±kta Kalan MCP SunucularÄ± (Exposed MCP Servers)
Trend Micro tarafÄ±ndan tespit edilen 492 aÃ§Ä±k MCP sunucusu, kimlik doÄŸrulamasÄ± veya ÅŸifreleme olmadan Ã§evrimiÃ§i eriÅŸime maruz; %90'Ä± doÄŸal dil sorgularÄ± ile hassas verilere (bulut kaynaklarÄ±, mÃ¼ÅŸteri bilgileri) doÄŸrudan okuma eriÅŸimi saÄŸlÄ±yor. KQL sorgularÄ± ile bu sunucularÄ±n avlanmasÄ± Ã¶neriliyor, ciddi veri sÄ±zÄ±ntÄ±sÄ± riski taÅŸÄ±yor.

Ä°lgili X postlarÄ±:
- https://x.com/0x534c/status/1956999290863370481

### Figma MCP Sunucusu Uzak Kod YÃ¼rÃ¼tme Zafiyeti (Figma MCP RCE Vulnerability)
Figma'nÄ±n MCP sunucusunda (CVE-2025-53967) tespit edilen kritik zafiyet, zararlÄ± API istekleri yoluyla uzak kod yÃ¼rÃ¼tmeye izin veriyor; AI prompt enjeksiyonu ve DNS rebinding ile sÃ¶mÃ¼rÃ¼lebilir. v0.6.3 sÃ¼rÃ¼mÃ¼ne gÃ¼ncelleme zorunlu, aksi halde sistemsel uzlaÅŸma mÃ¼mkÃ¼n.

Ä°lgili X postlarÄ±:
- https://x.com/freedomhack101/status/1976288100243607552
- https://x.com/shah_sheikh/status/1975889172872286316
- https://x.com/TweetThreatNews/status/1975997613221572728

### Sahte npm Paketi Arka KapÄ± OlayÄ± (Fake npm Package Backdoor - postmark-mcp)
postmark-mcp adlÄ± sahte npm paketi, her e-postayÄ± gizlice BCC ile saldÄ±rgana yÃ¶nlendirerek 1.600 indirmeden sonra kaldÄ±rÄ±ldÄ±; faturalar ve ÅŸifre sÄ±fÄ±rlamalarÄ± gibi verileri sÄ±zdÄ±rdÄ±. MCP tedarik zinciri saldÄ±rÄ±larÄ±nÄ± yansÄ±tÄ±yor, imzalÄ± kayÄ±tlar ve sandbox izinleri Ã¶neriliyor.

Ä°lgili X postlarÄ±:
- https://x.com/TheHackersNews/status/1972581724992528746
- https://x.com/theagentangle/status/1976018568413405335
- https://x.com/iamKierraD/status/1975226041309299085

### MCP GÃ¼venlik Kontrol Listesi (MCP Security Checklist)
SlowMist tarafÄ±ndan yayÄ±nlanan MCP gÃ¼venlik rehberi, ana bilgisayar, istemci ve sunucu katmanlarÄ±nda riskleri kapsÄ±yor; Ã§oklu MCP ve kripto para entegrasyonlarÄ±nda Ã¶zel tehditler vurgulanÄ±yor. AI ve blockchain ekosistemlerinin gÃ¼venli entegrasyonu iÃ§in temel Ã¶nlemler sunuyor.

Ä°lgili X postlarÄ±:
- https://x.com/SlowMist_Team/status/1911678320531607903

### MCP YÄ±ÄŸÄ±nlarÄ±nda %92 SÃ¶mÃ¼rÃ¼ OlasÄ±lÄ±ÄŸÄ± (92% Exploit Probability in MCP Stacks)
MCP eklenti yÄ±ÄŸÄ±nlarÄ±nda %92 sÃ¶mÃ¼rÃ¼ olasÄ±lÄ±ÄŸÄ±, kurumsal gÃ¼venlik kÃ¶r noktalarÄ±nÄ± artÄ±rÄ±yor; CVEs analizi ve savunma stratejileri, eriÅŸim sÄ±kÄ±laÅŸtÄ±rmasÄ± ve zayÄ±f noktalarÄ± tespit etmeyi Ã¶neriyor. Eklenti zincirleri bÃ¼yÃ¼k Ã¶lÃ§ekli sÃ¶mÃ¼rÃ¼lere yol aÃ§abiliyor.

Ä°lgili X postlarÄ±:
- https://x.com/jfrog/status/1976719975881617553
- https://x.com/LouisColumbus/status/1976393986156941725

### MCP Tehditlerinin Sistematik Ã‡alÄ±ÅŸmasÄ± (Systematic Study of MCP Threats)
MCP yaÅŸam dÃ¶ngÃ¼sÃ¼nde 16 tehdit senaryosu tanÄ±mlayan Ã§alÄ±ÅŸma, kÃ¶tÃ¼ niyetli geliÅŸtiriciler, kullanÄ±cÄ±lar ve dÄ±ÅŸ saldÄ±rganlarÄ± kapsÄ±yor; gerÃ§ek dÃ¼nya vakalarÄ±yla desteklenen faz bazlÄ± gÃ¼venlik Ã¶nlemleri Ã¶neriliyor. Interoperabilite iÃ§in gÃ¼venli benimseme yol haritasÄ± sunuyor.

Ä°lgili X postlarÄ±:
- https://x.com/jiqizhixin/status/1976109107804270655
- https://x.com/vlruso/status/1977603410690977952 (baÄŸlantÄ±lÄ± tartÄ±ÅŸma)

### MCP Prompt Enjeksiyonu ve Ajan GÃ¼venliÄŸi (MCP Prompt Injection and Agent Security)
MCP'de prompt enjeksiyonu, gÃ¼venilmeyen girdilere maruz kalan araÃ§lardan kaynaklanÄ±yor; Ã¶zellikle yerel ajanlarda (Cursor, Claude Code) risk yÃ¼ksek. BaÄŸlayÄ±cÄ±lar ve bellek Ã¶zellikleriyle birleÅŸince veri sÄ±zÄ±ntÄ±sÄ± artÄ±yor, araÃ§larÄ± sandbox'lama Ã¶neriliyor.

Ä°lgili X postlarÄ±:
- https://x.com/simonw/status/1909955640107430226
- https://x.com/karpathy/status/1934657940155441477
- https://x.com/Rajan_Medhekar/status/1977601624110768573
- https://x.com/liran_tal/status/1976362229294387584
- https://x.com/UndercodeUpdate/status/1977524734230229026

### MCP SunucularÄ±nda KÃ¶tÃ¼ye KullanÄ±m ve Kripto Entegrasyonu Tehditleri (MCP Plugin Abuse and Crypto Integration Risks)
MCP eklenti kÃ¶tÃ¼ye kullanÄ±mÄ± ve kripto entegrasyonlarÄ±, yeni gÃ¼venlik riskleri getiriyor; A2A (ajan-ajan) etkileÅŸimlerinde Ã§oÄŸaltÄ±cÄ± tehdit yÃ¼zeyi oluÅŸuyor. AI odaklÄ± savunmalar ve sÄ±fÄ±r gÃ¼ven mimarisi zorunlu.

Ä°lgili X postlarÄ±:
- https://x.com/DarkScorpionAI/status/1977435023147163737
- https://x.com/vietjovi/status/1977369607015956574
- https://x.com/eddy_crypt409/status/1915771464764076441


- **GÃ¼venlik EndiÅŸeleri TartÄ±ÅŸmalarÄ± Domine Ediyor**: AraÅŸtÄ±rmalar, MCP'nin araÃ§ zehirleme saldÄ±rÄ±larÄ±na karÅŸÄ± savunmasÄ±z olduÄŸunu gÃ¶steriyor. Bu saldÄ±rÄ±larda, kÃ¶tÃ¼ niyetli sunucular araÃ§ aÃ§Ä±klamalarÄ±na zararlÄ± komutlar yerleÅŸtirerek veri sÄ±zdÄ±rÄ±lmasÄ±na veya yetkisiz eylemlere yol aÃ§abiliyor. KanÄ±tlar, yÃ¼ksek istismar olasÄ±lÄ±klarÄ±na iÅŸaret ediyor. Raporlar, eklenti yÄ±ÄŸÄ±nlarÄ±nda %92'ye varan risk olduÄŸunu gÃ¶steriyor, ancak tarayÄ±cÄ±lar ve kontrol listeleri gibi savunma araÃ§larÄ± ortaya Ã§Ä±kmaya baÅŸlÄ±yor.
- **Son Zamanlarda Ortaya Ã‡Ä±kan GÃ¼venlik AÃ§Ä±klarÄ± ve SÃ¶mÃ¼rÃ¼ler**: Prompt enjeksiyonu ve eksik kimlik doÄŸrulama gibi kritik kusurlarÄ±n, sahte npm paketlerinin e-postalara arka kapÄ± aÃ§masÄ± gibi gerÃ§ek senaryolarda sÃ¶mÃ¼rÃ¼ldÃ¼ÄŸÃ¼ muhtemel gÃ¶rÃ¼nÃ¼yor. Topluluk analizleri, eski web gÃ¼venlik uygulamalarÄ±yla paralellikler kurarak, bu kusurlarÄ±n kolayca sÃ¶mÃ¼rÃ¼lebilir olduÄŸunu vurguluyor.
- **Yamalar, DÃ¼zeltmeler ve GÃ¼ncellemeler**: GeliÅŸmeler, yeni spesifikasyonlar (Ã¶rneÄŸin, yetkilendirmeyi geliÅŸtiren 2025-06-18 sÃ¼rÃ¼mÃ¼) ve zehirleme veya rug pull'larÄ± tespit eden MCP tarayÄ±cÄ±larÄ± gibi gÃ¼venlik araÃ§larÄ± dahil olmak Ã¼zere, devam eden iyileÅŸtirmelere iÅŸaret etmektedir. Claude, Cursor ve ChatGPT gibi platformlarla entegrasyonlar, iÅŸlevselliÄŸi geniÅŸletirken riskleri azaltmayÄ± amaÃ§lamaktadÄ±r.
- **GÃ¼ncel GeliÅŸmeler ve Entegrasyonlar**: Protokol, Spring AI, MuleSoft ve blok zinciri platformlarÄ± (Ã¶r. Rootstock, Cardano) gibi ekosistemlerde desteklenerek AI ajanlarÄ± iÃ§in yaygÄ±n olarak benimsenmektedir. Bu, birlikte Ã§alÄ±ÅŸabilirliÄŸi teÅŸvik etmekte ancak aÃ§Ä±k sunucular ve kimlik doÄŸrulama boÅŸluklarÄ± konusunda endiÅŸeleri artÄ±rmaktadÄ±r.
- **Topluluk ve Resmi TartÄ±ÅŸmalar**: TartÄ±ÅŸmalar, araÅŸtÄ±rmacÄ±larÄ±n ve ÅŸirketlerin faydalar ve riskler konusunda dengeli gÃ¶rÃ¼ÅŸleri vurgulayan analizleriyle, heyecan ve ihtiyatÄ±n karÄ±ÅŸÄ±mÄ± bir havayÄ± yansÄ±tmaktadÄ±r. Resmi duyurular, AI araÃ§ baÄŸlantÄ±larÄ± iÃ§in standardizasyona odaklanÄ±rken, tartÄ±ÅŸmalar AI tabanlÄ± ekonomilerin potansiyelini kabul etmekle birlikte, test edilmemiÅŸ uygulamalar konusunda uyarÄ±da bulunmaktadÄ±r.
### MCP'ye Genel BakÄ±ÅŸ
Model Context Protocol (MCP), AI modelleri ve harici araÃ§lar arasÄ±nda Ã§ift yÃ¶nlÃ¼ iletiÅŸim iÃ§in aÃ§Ä±k bir standart gÃ¶revi gÃ¶rÃ¼r ve parÃ§alanmÄ±ÅŸ AI ekosistemlerini birleÅŸtirir. Claude Desktop ve Cursor gibi uygulamalarda uygulanÄ±r ve sorunsuz entegrasyonlar saÄŸlar, ancak eklenti kÃ¶tÃ¼ye kullanÄ±mÄ± gibi yeni riskler getirir. Son zamanlarda yayÄ±nlanan yazÄ±lar, ajanlarÄ±n veri kaynaklarÄ±na zahmetsizce baÄŸlandÄ±ÄŸÄ± ajans AI'daki rolÃ¼nÃ¼ vurgulamaktadÄ±r, ancak bu durum gÃ¼venlik kÃ¶r noktalarÄ±nÄ± artÄ±rmaktadÄ±r.
### Ã–nemli GÃ¼venlik AÃ§Ä±klarÄ±
AraÃ§ zehirlenmesi kritik bir sorun olarak Ã¶ne Ã§Ä±kmaktadÄ±r: KÃ¶tÃ¼ niyetli MCP sunucularÄ±, kullanÄ±cÄ± onaylarÄ±nÄ± atlayarak ve zararsÄ±z gÃ¶rÃ¼nÃ¼m altÄ±nda zararlÄ± eylemler gerÃ§ekleÅŸtirerek gizli komutlar enjekte edebilir. DiÄŸer aÃ§Ä±klar arasÄ±nda, aÃ§Ä±kta kalan sunucular (Ã§evrimiÃ§i olarak 492 tane bulunmuÅŸtur), komut enjeksiyonu ve bozuk kimlik doÄŸrulama yer almaktadÄ±r ve bunlar genellikle â€œkolayâ€ olarak deÄŸerlendirilmektedir. Sahte npm paketinin e-postalarÄ± Ã§almasÄ± gibi gerÃ§ek hayattaki olaylar, bu konunun aciliyetini vurgulamaktadÄ±r.
### Savunmadaki GeliÅŸmeler
Tehditlere karÅŸÄ± koyma Ã§abalarÄ± arasÄ±nda, ana bilgisayar, istemci ve sunucu katmanlarÄ±nÄ± kapsayan gÃ¼venlik kontrol listeleri ve saldÄ±rÄ±larÄ± tespit etmek iÃ§in Ã¶zel tarayÄ±cÄ±lar bulunmaktadÄ±r. Yamalar, Figma'nÄ±n MCP sunucusunda uzaktan kod yÃ¼rÃ¼tÃ¼lmesine izin veren gibi belirli gÃ¼venlik aÃ§Ä±klarÄ±nÄ± giderir. Vulnerablemcp[.]info gibi topluluk kaynaklarÄ±, saldÄ±rÄ±larÄ± anlamaya ve Ã¶nlemeye yardÄ±mcÄ± olmak iÃ§in saldÄ±rÄ± Ã¶zetleri sunar.
### Ekosistem BÃ¼yÃ¼mesi
MCP, blok zincirinden (Ã¶r. DeMCP_AI pazarÄ±) geliÅŸtirici araÃ§larÄ±na (Ã¶r. tarayÄ±cÄ± kontrolÃ¼ iÃ§in Chrome DevTools) kadar Ã§eÅŸitli platformlarla entegre olmaktadÄ±r. GÃ¼ncellemeler, gÃ¼venli Ã¶lÃ§eklendirme iÃ§in daha iyi yetkilendirme gibi kurumsal Ã¶zellikleri geliÅŸtirir. Ancak tartÄ±ÅŸmalar, mevcut API'lerle uyumsuzluk ve uzaktan kurulumlarda kimlik doÄŸrulama zorluklarÄ± gibi sÄ±nÄ±rlamalarÄ± vurgulamaktadÄ±r.
---
Model Context Protocol (MCP), AI alanÄ±nda Ã¶nemli bir aÃ§Ä±k standart olarak ortaya Ã§Ä±kmÄ±ÅŸ ve bÃ¼yÃ¼k dil modelleri (LLM'ler) ile harici araÃ§lar veya veri kaynaklarÄ± arasÄ±nda kesintisiz Ã§ift yÃ¶nlÃ¼ iletiÅŸimi kolaylaÅŸtÄ±rmÄ±ÅŸtÄ±r. AI ekosistemlerindeki parÃ§alanmayÄ± gidermek iÃ§in tasarlanan MCP, tak ve Ã§alÄ±ÅŸtÄ±r entegrasyonlarÄ±nÄ± mÃ¼mkÃ¼n kÄ±larak AI ajanlarÄ±nÄ±n gerÃ§ek zamanlÄ± verilere eriÅŸmesine, eylemleri gerÃ§ekleÅŸtirmesine ve Ã¶zel kodlama olmadan Ã§eÅŸitli sistemlerle etkileÅŸime girmesine olanak tanÄ±r. Genellikle AI iÃ§in TCP/IP'ye benzetilen bu protokol, masaÃ¼stÃ¼ ortamlarÄ±ndaki uygulamalarÄ± (Ã¶r. Claude Desktop, Cursor), blok zinciri pazarlarÄ±nÄ± ve kurumsal yÄ±ÄŸÄ±nlarÄ± destekleyerek geliÅŸtirme karmaÅŸÄ±klÄ±ÄŸÄ±nÄ± azaltÄ±r ve modÃ¼ler AI iÅŸ akÄ±ÅŸlarÄ±nÄ±n Ã¶nÃ¼nÃ¼ aÃ§ar. Ancak, hÄ±zlÄ± benimsenmesi Ã¶nemli gÃ¼venlik sorunlarÄ±nÄ± gÃ¼ndeme getirmiÅŸtir. GeÃ§tiÄŸimiz yÄ±l yapÄ±lan tartÄ±ÅŸmalar, umut verici dÃ¼zeltmeler, gÃ¼ncellemeler ve topluluk odaklÄ± analizlerin yanÄ± sÄ±ra, erken web geliÅŸtirme tuzaklarÄ±nÄ± anÄ±msatan gÃ¼venlik aÃ§Ä±klarÄ±nÄ± ortaya Ã§Ä±karmÄ±ÅŸtÄ±r.
### Evrim ve Teknik Temeller
MCP'nin temel mimarisi Ã¼Ã§ katman etrafÄ±nda dÃ¶ner: model (iÅŸlemlerin ve verilerin standart temsilleri), baÄŸlam (aÄŸ parametreleri gibi Ã§evresel ayrÄ±ntÄ±lar) ve protokol (eylemleri oluÅŸturma ve gÃ¶nderme mantÄ±ÄŸÄ±). Bu modÃ¼lerlik, OpenAI, Anthropic ve Google gibi saÄŸlayÄ±cÄ±larÄ±n LLM'leri arasÄ±nda birlikte Ã§alÄ±ÅŸabilirliÄŸi destekler. 2025-06-18 gÃ¼ncellemesi gibi son spesifikasyonlar, kurumsal kullanÄ±m iÃ§in geliÅŸtirilmiÅŸ yetkilendirme, elde etme mekanizmalarÄ± ve kaynak baÄŸlantÄ±larÄ± gibi iyileÅŸtirmeler getirerek gÃ¼venli, Ã¶lÃ§eklenebilir AI sistemleri oluÅŸturmayÄ± kolaylaÅŸtÄ±rmÄ±ÅŸtÄ±r. Teknik tartÄ±ÅŸmalar, MCP'nin yerel bir masaÃ¼stÃ¼ protokolÃ¼ (kamu trafiÄŸi iÃ§in SSE ile stdio Ã¼zerinde Ã§alÄ±ÅŸan) olarak ortaya Ã§Ä±kÄ±ÅŸÄ±nÄ± vurgulamaktadÄ±r. Bu, kimlik doÄŸrulama engellerini (baÅŸlÄ±klar veya Ã§erezler iÃ§in yerel destek eksikliÄŸi) ve bunlarÄ± gidermek iÃ§in AI API aÄŸ geÃ§itlerinin yÃ¼kseliÅŸini aÃ§Ä±klamaktadÄ±r. Entegrasyonlar, blok zincirine (Ã¶r. zincir Ã¼zerinde geliÅŸtirme iÃ§in Rootstock MCP Sunucusu, iÅŸlem oluÅŸturma iÃ§in Cardano) ve geliÅŸtirme araÃ§larÄ±na (Ã¶r. tarayÄ±cÄ± hata ayÄ±klama iÃ§in Chrome DevTools, AI'nÄ±n DOM'u incelemesine, UI testleri Ã§alÄ±ÅŸtÄ±rmasÄ±na ve ekran gÃ¶rÃ¼ntÃ¼leri ile dÃ¼zeltmeleri doÄŸrulamasÄ±na olanak tanÄ±r) kadar uzanmaktadÄ±r. Kurumsal baÄŸlamlarda, Spring AI ve MuleSoft MCP gibi Ã§erÃ§eveler HTTP, zamanlama ve hata toleransÄ± iÃ§in bildirimsel API'leri desteklerken, Amazon Bedrock AgentCore dakikalar iÃ§inde Ã¼retime hazÄ±r AI ajanlarÄ± saÄŸlar.
### GÃ¼venlik AÃ§Ä±klarÄ± ve GÃ¼venlik KusurlarÄ±
GÃ¼venlik tartÄ±ÅŸmalarÄ± MCP ile ilgili iÃ§eriÄŸi domine ederken, araÃ§ zehirlenmesi kritik bir tehdit olarak ortaya Ã§Ä±kmaktadÄ±r. Bu saldÄ±rÄ±larda, kÃ¶tÃ¼ niyetli sunucular araÃ§ aÃ§Ä±klamalarÄ±na zararlÄ± talimatlar yerleÅŸtirir ve AI asistanlarÄ± bunlarÄ± komut istemlerine dahil eder, bÃ¶ylece kullanÄ±cÄ±lar gÃ¶rÃ¼nÃ¼ÅŸte zararsÄ±z talepleri onaylarken veri sÄ±zÄ±ntÄ±larÄ± (Ã¶r. SSH anahtarlarÄ±, API anahtarlarÄ±) gibi yetkisiz eylemler gerÃ§ekleÅŸir. Sistematik bir Ã§alÄ±ÅŸma, kÃ¶tÃ¼ niyetli geliÅŸtiriciler, kullanÄ±cÄ±lar veya dÄ±ÅŸ saldÄ±rganlarÄ±n dahil olduÄŸu, oluÅŸturulmasÄ±ndan bakÄ±mÄ±na kadar MCP yaÅŸam dÃ¶ngÃ¼sÃ¼ boyunca 16 tehdit senaryosu belirlemiÅŸtir. AÃ§Ä±ÄŸa Ã§Ä±kan sunucular baÅŸka bir risk oluÅŸturmaktadÄ±r: Trend Micro, kimlik doÄŸrulama veya ÅŸifreleme olmadan 492 Ã§evrimiÃ§i Ã¶rnek bildirmiÅŸtir. Bu Ã¶rnekler, doÄŸal dil sorgularÄ± yoluyla bulut kaynaklarÄ± gibi hassas verilere doÄŸrudan okuma eriÅŸimi saÄŸlamaktadÄ±r. Komut istemine enjeksiyon, komut enjeksiyonu ve eksik kimlik doÄŸrulama â€” 25 en Ã¶nemli gÃ¼venlik aÃ§Ä±ÄŸÄ±ndan 18'inde â€œkolayâ€ olarak deÄŸerlendirilen kusurlar â€” yÄ±llar Ã¶nce web geliÅŸtirmede Ã§Ã¶zÃ¼len sorunlarÄ± yansÄ±tmaktadÄ±r, ancak cÃ¶mert izinlere sahip AI ajanlarÄ±nda hala devam etmektedir. GerÃ§ek dÃ¼nyadaki istismarlar arasÄ±nda, saldÄ±rganlara e-postalarÄ± gizli kopya olarak gÃ¶nderen ve kaldÄ±rÄ±lmadan Ã¶nce 1.600 kez indirilen sahte bir npm paketi (â€œpostmark-mcpâ€) ve uzaktan kod yÃ¼rÃ¼tmeyi mÃ¼mkÃ¼n kÄ±lan bir Figma MCP kusuru bulunmaktadÄ±r. Analizler, eklenti yÄ±ÄŸÄ±nlarÄ±nda %92 istismar olasÄ±lÄ±ÄŸÄ± olduÄŸu konusunda uyarÄ±da bulunarak, kÃ¼Ã§Ã¼k zayÄ±flÄ±klarÄ± bÃ¼yÃ¼k Ã¶lÃ§ekli ihlallere dÃ¶nÃ¼ÅŸtÃ¼rmektedir. HÄ±zlÄ± enjeksiyon, MCP'ye Ã¶zgÃ¼ deÄŸildir, ancak araÃ§larÄ±n gÃ¼venilmeyen girdilere maruz kalmasÄ±ndan kaynaklanÄ±r ve ajanlar arasÄ± (A2A) etkileÅŸimlerde riskleri artÄ±rÄ±r.
| GÃ¼venlik AÃ§Ä±ÄŸÄ± TÃ¼rÃ¼ | AÃ§Ä±klama | SÃ¶mÃ¼rÃ¼ KolaylÄ±ÄŸÄ± | Etki | TartÄ±ÅŸmalardan Ã–rnekler |
|--------------------|------------ -|--------------|--------|---------------------------|
| AraÃ§ Zehirlenmesi | AraÃ§ aÃ§Ä±klamalarÄ±nda gizlenmiÅŸ kÃ¶tÃ¼ amaÃ§lÄ± talimatlar | Kolay | Veri sÄ±zdÄ±rma, yetkisiz eylemler | MCP sunucularÄ± Ã¼zerinden dÃ¼ÅŸmanca saldÄ±rÄ±lar; SSH/API anahtarlarÄ±nÄ±n sÄ±zdÄ±rÄ±lmasÄ± |
| AÃ§Ä±ÄŸa Ã‡Ä±kmÄ±ÅŸ Sunucular | Kimlik doÄŸrulamasÄ± yapÄ±lmamÄ±ÅŸ Ã§evrimiÃ§i Ã¶rnekler | Ã–nemsiz | Hassas verilere arka kapÄ± | 492 sunucu bulundu; %90'Ä± doÄŸal dil eriÅŸimine izin veriyor |
| Komut/Emir Enjeksiyonu | GiriÅŸ doÄŸrulamasÄ±nÄ± atlama | Kolay | Sistem gÃ¼venliÄŸinin ihlali | Ä°lk 25 rapor: 18/25 istismar edilebilir; yamalanmamÄ±ÅŸ PHP ile paralellikler |
| Eksik Kimlik DoÄŸrulama | BaÅŸlÄ±k/Ã§erez desteÄŸi yok | Orta | Yetkisiz eriÅŸim | Uzaktan kurulumlar savunmasÄ±z; rug pull/Ã§apraz kaynak sorunlarÄ±na yol aÃ§ar |
| Eklenti KÃ¶tÃ¼ye KullanÄ±mÄ± | YÄ±ÄŸÄ±nlarda tehlikeye atÄ±lmÄ±ÅŸ eklentiler | YÃ¼ksek (%92 olasÄ±lÄ±k) | Kurumsal Ã§apta istismarlar | E-postalarÄ± Ã§alan sahte npm paketleri; Figma uzaktan kod yÃ¼rÃ¼tme |
### Yamalar, DÃ¼zeltmeler ve Azaltma Stratejileri
Tehditlere karÅŸÄ± alÄ±nan Ã¶nlemler arasÄ±nda Figma'nÄ±n gÃ¼venlik aÃ§Ä±ÄŸÄ± dÃ¼zeltmesi gibi belirli kusurlar iÃ§in yamalar ve SlowMist gibi firmalarÄ±n Ã§oklu MCP ve kripto para senaryolarÄ±nÄ± kapsayan kapsamlÄ± kontrol listeleri bulunmaktadÄ±r. GÃ¼venlik tarayÄ±cÄ±larÄ±, Claude ve Cursor gibi araÃ§larÄ± destekleyerek araÃ§ zehirlenmesi, rug pull (hash yoluyla) ve Ã§apraz kaynak ihlallerini tespit eder. Vulnerablemcp[.]info gibi kaynaklar, daha iyi savunma iÃ§in saldÄ±rÄ± vektÃ¶rlerini ayrÄ±ntÄ±lÄ± olarak aÃ§Ä±klar. En iyi uygulamalar, kÃ¶tÃ¼ amaÃ§lÄ± yazÄ±lÄ±m gibi sunucularÄ± incelemeyi, kapsamlarÄ± sÄ±nÄ±rlandÄ±rmayÄ±, gÃ¼venilir saÄŸlayÄ±cÄ±larÄ± kullanmayÄ± ve gÃ¼ncellemelerden sonra MCP'leri yeniden onaylamayÄ± vurgular. KQL sorgularÄ±, Microsoft Sentinel gibi ortamlarda maruz kalan sunucularÄ± bulmaya yardÄ±mcÄ± olur. Daha geniÅŸ savunma Ã¶nlemleri arasÄ±nda AI destekli gÃ¼venlik Ã¶nlemleri, aÅŸama Ã¶zel korumalar ve sohbetlerdeki UI Ã¶ÄŸeleri iÃ§in MCP-UI gibi standartlar bulunur.
### GÃ¼ncel GeliÅŸmeler ve Entegrasyonlar
MCP'nin bÃ¼yÃ¼mesi, ChatGPT GeliÅŸtirici Modu, VS Code (GitHub MCP kayÄ±t defteri ile v1.105) ve n8n iÅŸ akÄ±ÅŸlarÄ± iÃ§in TypingMind gibi platformlarda tam desteÄŸi iÃ§erir. DeMCP_AI'nin AI hesaplama iÃ§in Web3 pazarÄ± ve TaironAI'nin Oracle KatmanÄ± gibi blok zinciri entegrasyonlarÄ±, zincir Ã¼zerinde gÃ¼venlik ve modÃ¼ler araÃ§lar iÃ§in MCP'yi kullanÄ±r. Otto MCP ve Briq'in Otonom Ä°ÅŸ GÃ¼cÃ¼ Platformu gibi kurumsal araÃ§lar, MCP'yi AI iÃ§in â€œaÃ§Ä±k anâ€ olarak konumlandÄ±rarak ajanlarÄ±n Ã¶zerkliÄŸini saÄŸlar. Helidon 4.3.0 ve Hugging Face MCP Sunucusu gibi aÃ§Ä±k kaynak Ã§abalarÄ±, yÃ¶netim API paritesi ve UI desteÄŸi gibi Ã¶zellikler ekler. KatalizÃ¶r Ã¶nerileri, MCP aracÄ±lÄ±ÄŸÄ±yla Cardano iÅŸlemlerini AI ile desteklemeyi amaÃ§lamaktadÄ±r.
### Topluluk TartÄ±ÅŸmalarÄ± ve Analizleri
Analizler dengeli gÃ¶rÃ¼ÅŸleri vurgulamaktadÄ±r: MCP verimliliÄŸi artÄ±rÄ±r (Ã¶rneÄŸin, ajanlarda %97,3 araÃ§ Ã§aÄŸÄ±rma gÃ¼venilirliÄŸi) ancak â€œpahalÄ± derslerâ€den kaÃ§Ä±nmak iÃ§in disiplin gerektirir. Reddit ve Zenn.dev gibi platformlarda yapÄ±lan tartÄ±ÅŸmalar Japon baÄŸlamÄ±ndaki riskleri ele alÄ±rken, makaleler yÃ¼kselen gÃ¼venlik manzaralarÄ±nÄ± incelemektedir. Topluluk, Jenova.ai'nin MCP'ye Ã¶zel ajanÄ± ve iÃ§erik yÃ¶netimi iÃ§in Umbraco CMS MCP Beta gibi yeniliklere dikkat Ã§ekiyor. TartÄ±ÅŸmalar arasÄ±nda MCP'nin OpenAPI ÅŸemalarÄ±yla uyumsuzluÄŸu ve Story Protocol gibi entegrasyonlar yoluyla AI'nÄ±n sahip olduÄŸu IP potansiyeli yer alÄ±yor.
### Resmi Duyurular ve Gelecekteki YÃ¶nelimler
Anthropic, OpenAI ve Google gibi kuruluÅŸlarÄ±n duyurularÄ±, MCP'nin AI arama alÄ±ntÄ±larÄ± ve geliÅŸtirme araÃ§larÄ±ndaki rolÃ¼nÃ¼ vurgulamaktadÄ±r. Devoxx gibi etkinliklerde MCP Java SDK ile ilgili uygulamalÄ± oturumlar dÃ¼zenlenmektedir. Gelecekteki beklentiler, AI API aÄŸ geÃ§itleri, ajanlar arasÄ± iletiÅŸim ve MCP-UI gibi standartlarÄ±n kullanÄ±labilirliÄŸi artÄ±rÄ±rken eksiklikleri gidermesini Ã¶ngÃ¶rmektedir. Genel olarak, MCP'nin gidiÅŸatÄ± yenilikÃ§ilik ile gÃ¼venlik gereklilikleri arasÄ±nda bir denge kurarak, onu AI'nÄ±n bir sonraki aÅŸamasÄ± iÃ§in vazgeÃ§ilmez bir unsur haline getirmektedir.
**Ã–nemli AlÄ±ntÄ±lar:**
- [Graham_dePenros, AraÃ§ Zehirleme SaldÄ±rÄ±larÄ± hakkÄ±nda](https://x.com/Graham_dePenros/status/1976216281033408741)
- [lbeurerkellner, Kritik Kusur KeÅŸfi](https://x.com/lbeurerkellner/status/1907075048118059101)
- [jfrog, SÃ¶mÃ¼rÃ¼ OlasÄ±lÄ±ÄŸÄ± hakkÄ±nda](https://x.com/jfrog/status/1976719975881617553)
- [SlowMist_Team, GÃ¼venlik Kontrol Listesi hakkÄ±nda](https://x.com/SlowMist_Team/status/1911678320531607903)
- [rryssf_ En Ã–nemli 25 GÃ¼venlik AÃ§Ä±ÄŸÄ±](https://x.com/rryssf_/status/1970524674439422444)
- [LouisColumbus, Eklenti Riskleri hakkÄ±nda](https://x.com/LouisColumbus/status/1976393986156941725)
- [rez0__, GÃ¼venlik AÃ§Ä±ÄŸÄ± KaynaÄŸÄ± hakkÄ±nda](https://x.com/rez0__/status/1922381770588053669)
- [liran_tal, GÃ¼venlik OrtamÄ± hakkÄ±nda](https://x.com/liran_tal/status/1976362229294387584)
- [jiqizhixin, Sistematik Ã‡alÄ±ÅŸma GÃ¼ncellemesi](https://x.com/jiqizhixin/status/1976109107804270655)
- [0x534c, AÃ§Ä±ÄŸa Ã‡Ä±kmÄ±ÅŸ Sunucular hakkÄ±nda](https://x.com/0x534c/status/1956999290863370481)
- [simonw, HÄ±zlÄ± Enjeksiyon SorunlarÄ± hakkÄ±nda](https://x.com/simonw/status/1909955640107430226)
- [Chikor_Zi, Åema SÄ±nÄ±rlamalarÄ± hakkÄ±nda](https://x.com/Chikor_Zi/status/1939362725630562592)
- [TheHackersNews, Arka KapÄ± OlayÄ± hakkÄ±nda](https://x.com/TheHackersNews/status/1972581724992528746)
- [dsp_, Yeni Spesifikasyon hakkÄ±nda](https://x.com/dsp_/status/1935740870680363328)
- [kakarot_ai, KorkunÃ§ GÃ¼venlik AÃ§Ä±klarÄ± hakkÄ±nda](https://x.com/kakarot_ai/status/1975599529681690820)
- [lbeurerkellner, GÃ¼venlik TarayÄ±cÄ±sÄ± hakkÄ±nda](https://x.com/lbeurerkellner/status/1910379084758343827)
- [MCP_Community, ÃœrÃ¼n Ã–zeti hakkÄ±nda](https://x.com/MCP_Community/status/1951369789685084254)
- [nutrientdocs, MCP SunucularÄ±nÄ±n Tedavisi hakkÄ±nda](https://x.com/nutrientdocs/status/1976707785548030101)
- [GoogleCloudTech, Gemini CLI Entegrasyonu hakkÄ±nda](https://x.com/GoogleCloudTech/status/1973493121250902040)
- [rootstock_io, Rootstock MCP Sunucusu hakkÄ±nda](https://x.com/rootstock_io/status/1975656743799902686)
- [nowitnesslabs, Catalyst Ã–nerisi hakkÄ±nda](https://x.com/nowitnesslabs/status/1972563255479459990)
- [BriqHQ, OTTO MCP Duyurusu hakkÄ±nda](https://x.com/BriqHQ/status/1972723699016183888)
- [evalstate, HF MCP Sunucusu hakkÄ±nda](https://x.com/evalstate/status/1975188323124519293)
- [100xDarren, TAIRO GÃ¼ncellemesi hakkÄ±nda](https://x.com/100xDarren/status/1973515775593029886)
- [KrekhovetsRZ, Story Protocol Entegrasyonu hakkÄ±nda](https://x.com/KrekhovetsRZ/status/1975278135961702515)
- [helidon_project, Helidon 4.3.0 SÃ¼rÃ¼mÃ¼ hakkÄ±nda](https://x.com/helidon_project/status/1973727994742239401)
- [ChromiumDev, DevTools MCP hakkÄ±nda](https://x.com/ChromiumDev/status/1976422660880875687)
- [christzolov, Devoxx Talk hakkÄ±nda](https://x.com/christzolov/status/1976209066423947619)
- [Bedrock AgentCore'da awsdevelopers](https://x.com/awsdevelopers/status/1974900254349603273)
- [lilyraynyc, AI Search Citations hakkÄ±nda](https://x.com/lilyraynyc/status/1973044734206628353)
- [HexawareGlobal, MuleSoft DesteÄŸi hakkÄ±nda](https://x.com/HexawareGlobal/status/1975546653667963028)
- [umbraco, CMS MCP Beta hakkÄ±nda](https://x.com/umbraco/status/1975463678733414582)
- [VS Code SÃ¼rÃ¼mÃ¼nde code](https://x.com/code/status/1976332459886182627)
- [n8n Entegrasyonunda TypingMindApp](https://x.com/TypingMindApp/status/1973767427872772513)

### AI AjanlarÄ± GÃ¼venlik Protokolleri

AraÅŸtÄ±rmalar, AI ajanlarÄ±nÄ±n (otonom gÃ¶revleri yerine getiren AI sistemleri) gÃ¼venlik risklerinin yÃ¼ksek olduÄŸunu gÃ¶steriyor; prompt enjeksiyonu, veri sÄ±zÄ±ntÄ±sÄ± ve kÃ¶tÃ¼ye kullanÄ±m gibi tehditler yaygÄ±n. Ancak, katmanlÄ± savunmalar ve en iyi uygulamalarla bu riskler yÃ¶netilebilir.

- **Temel Riskler**: AI ajanlarÄ±, LLM'lerin (bÃ¼yÃ¼k dil modelleri) aÃ§Ä±klÄ±klarÄ±ndan etkilenerek veri zehirlenmesi, jailbreak ve araÃ§ zehirlenmesi gibi saldÄ±rÄ±lara maruz kalÄ±r; bu, gizlilik ve bÃ¼tÃ¼nlÃ¼k ihlallerine yol aÃ§abilir.
- **Ana Savunmalar**: En az yetki ilkesi, giriÅŸ/Ã§Ä±kÄ±ÅŸ doÄŸrulamasÄ± ve sandboxing gibi geleneksel yÃ¶ntemler, AI'ye Ã¶zgÃ¼ guard modelleri ve davranÄ±ÅŸ sertifikalarÄ± ile birleÅŸtirilerek etkili koruma saÄŸlar.
- **Potansiyel TartÄ±ÅŸmalar**: BazÄ± uzmanlar, AI ajanlarÄ±nÄ±n tam Ã¶zerkliÄŸinin riskleri artÄ±rdÄ±ÄŸÄ±nÄ± savunurken, diÄŸerleri katÄ± protokollerle dengelenebileceÄŸini belirtiyor; ancak, standartlaÅŸma eksikliÄŸi genel bir endiÅŸe kaynaÄŸÄ±.

#### GiriÅŸ DoÄŸrulamasÄ± ve Sandboxing
GiriÅŸlerin sÄ±kÄ± doÄŸrulanmasÄ± (Ã¶rneÄŸin, JSON formatÄ± ve regex filtreleri) ve ajanlarÄ±n izole ortamlarda (sandbox) Ã§alÄ±ÅŸtÄ±rÄ±lmasÄ±, prompt enjeksiyonu gibi saldÄ±rÄ±larÄ± Ã¶nler. Bu, ajanlarÄ±n yalnÄ±zca gerekli kaynaklara eriÅŸmesini saÄŸlar.

#### Åifreleme ve Ä°zleme
TÃ¼m verilerin uÃ§tan uca ÅŸifrelenmesi (TLS 1.3, AES-256) ve davranÄ±ÅŸ izlemesi (OpenTelemetry gibi araÃ§larla), anormallikleri erken tespit eder. Rate limiting, DoS saldÄ±rÄ±larÄ±nÄ± sÄ±nÄ±rlayarak ajanlarÄ±n kullanÄ±labilirliÄŸini korur.

#### Protokol Spesifik YaklaÅŸÄ±mlar
A2AS gibi Ã§erÃ§eveler, davranÄ±ÅŸ sertifikalarÄ± ve baÄŸlam bÃ¼tÃ¼nlÃ¼ÄŸÃ¼ ile ajan-ajan iletiÅŸimini gÃ¼vence altÄ±na alÄ±r. MCP (Model Context Protocol) iÃ§in araÃ§ zehirlenmesi tarayÄ±cÄ±larÄ± Ã¶nerilir.

---

AI ajanlarÄ±, bÃ¼yÃ¼k dil modelleri (LLM'ler) Ã¼zerine kurulu otonom sistemler olarak, Ã§eÅŸitli gÃ¼venlik tehditleriyle karÅŸÄ± karÅŸÄ±ya kalÄ±r. Bu tehditler, geleneksel yazÄ±lÄ±m gÃ¼venlik sorunlarÄ±ndan farklÄ± olarak, ajanlarÄ±n karar alma ve eylem yÃ¼rÃ¼tme yeteneklerinden kaynaklanÄ±r. AraÅŸtÄ±rmalar, ajanlarÄ±n gizlilik, bÃ¼tÃ¼nlÃ¼k ve kullanÄ±labilirlik aÃ§Ä±sÄ±ndan risk taÅŸÄ±dÄ±ÄŸÄ±nÄ± vurgular; Ã¶rneÄŸin, prompt enjeksiyonu yoluyla zararlÄ± eylemler tetiklenebilir veya veri sÄ±zÄ±ntÄ±larÄ± meydana gelebilir. Bu kapsamlÄ± inceleme, son bir yÄ±ldaki web ve X (eski Twitter) kaynaklarÄ±ndan derlenen bilgileri temel alÄ±r, tehdit modellerini, saldÄ±rÄ± vektÃ¶rlerini ve savunma stratejilerini detaylandÄ±rÄ±r. Geleneksel ve AI'ye Ã¶zgÃ¼ yÃ¶ntemler bir araya getirilerek katmanlÄ± bir yaklaÅŸÄ±m Ã¶nerilir.

#### Tehdit Modelleri ve SaldÄ±rÄ± VektÃ¶rleri
AI ajanlarÄ±nÄ±n tehdit modeli, metin tabanlÄ± giriÅŸ/Ã§Ä±kÄ±ÅŸa dayanÄ±r; gÃ¼venli bir sunucuda barÄ±ndÄ±rÄ±lÄ±rken, kullanÄ±cÄ± eriÅŸimi API ile sÄ±nÄ±rlÄ±dÄ±r. Ancak, LLM'lerin Ã¼rettiÄŸi eylemler, sistem aÃ§Ä±klÄ±klarÄ±nÄ± istismar edebilir. Ana vektÃ¶rler ÅŸÃ¶yle:

1. **Oturum YÃ¶netimi AÃ§Ä±klarÄ±**: Ã‡ok kullanÄ±cÄ±lÄ± ajanlarda oturum izolasyonu eksikliÄŸi, bilgi sÄ±zÄ±ntÄ±sÄ±na (gizlilik ihlali) veya yanlÄ±ÅŸ eylem atamasÄ±na (bÃ¼tÃ¼nlÃ¼k ihlali) yol aÃ§ar. Kaynak yoÄŸun sorgularla DoS saldÄ±rÄ±larÄ± mÃ¼mkÃ¼n olur.
2. **Model Kirlenmesi ve Gizlilik SÄ±zÄ±ntÄ±larÄ±**: KullanÄ±cÄ± sohbet geÃ§miÅŸleriyle ince ayarlanmÄ±ÅŸ modeller, veri zehirlenmesine aÃ§Ä±ktÄ±r. Hassas veriler (SSN, hesap numaralarÄ±) LLM'lerde saklanarak Ã§Ä±karÄ±labilir; Ã¶rnek olarak Samsung'un ChatGPT yasaÄŸÄ± verilebilir.
3. **Ajan ProgramÄ± AÃ§Ä±klarÄ±**:
   - **SÄ±fÄ±r AtÄ±ÅŸ Eylemleri**: HalÃ¼sinasyonlar veya jailbreak'ler, istenmeyen komutlar Ã¼retir; araÃ§ belgelerine gÃ¶mÃ¼lÃ¼ prompt'lar veri sÄ±zÄ±ntÄ±sÄ±na neden olur.
   - **BiliÅŸsel Planlama**: ReAct veya Tree-of-Thoughts gibi yÃ¶ntemler, her adÄ±mda yan etkiler yaratÄ±r; kaynak tÃ¼ketimiyle kullanÄ±labilirlik etkilenir.
   Deneyler (BashAgent ile 95 gÃ¼venlik gÃ¶revi), kÄ±sÄ±tsÄ±z ortamlarda %96 gizlilik, %85.7 bÃ¼tÃ¼nlÃ¼k ve %62.9 kullanÄ±labilirlik saldÄ±rÄ±larÄ±nÄ±n baÅŸarÄ±lÄ± olduÄŸunu gÃ¶sterir.

X tartÄ±ÅŸmalarÄ±nda, araÃ§ zehirlenmesi (tool poisoning) ve plan enjeksiyonu gibi yeni saldÄ±rÄ±lar Ã¶ne Ã§Ä±kar; Ã¶rneÄŸin, ajan hafÄ±zasÄ±na gizli talimatlar eklenerek kalÄ±cÄ± zarar verilebilir.

TÃ¼rkÃ§e kaynaklarda, MCP (Model Context Protocol) gibi protokollerde araÃ§ zehirlenmesi ve ajan-ajan (A2A) iletiÅŸim riskleri vurgulanÄ±r; kÃ¶tÃ¼ niyetli sunucular, gizli talimatlarla veri dÄ±ÅŸa aktarÄ±mÄ± saÄŸlar.

#### Savunma Stratejileri
Savunmalar, bileÅŸen dÃ¼zeyinde odaklanÄ±r; izolasyon, ÅŸifreleme ve resmi modelleme ile uygulanÄ±r.

1. **Oturum YÃ¶netimi**: Benzersiz oturum kimlikleri ve KVDB ile tarihÃ§eyi izole edin; durum dÃ¶nÃ¼ÅŸtÃ¼rÃ¼cÃ¼ monadlar (state transformer monads) ile doÄŸrulanabilir hesaplamalar saÄŸlayÄ±n.
2. **Model KorumasÄ±**:
   - **Oturumsuz Modeller**: Ã–zel verileri filtreleyin; FPETS (Format-Preserving Encryption for Text Slicing) ile ÅŸifreleme, baÅŸarÄ± oranlarÄ±nÄ± %38-89 korur. FHE (Fully Homomorphic Encryption) hesaplamalara izin verir.
   - **Oturum FarkÄ±ndalÄ±ÄŸÄ±**: Prompt tuning ile kullanÄ±cÄ±ya Ã¶zgÃ¼ parametreler ekleyin, temel LLM'yi dondurun.
3. **Sandboxing**: Kaynak sÄ±nÄ±rlamalarÄ± ve Docker gibi izole ortamlar; kÄ±sÄ±tlÄ± BashAgent, tÃ¼m saldÄ±rÄ±larÄ± engeller. Beyaz/siyah listeler ve rate limiting, uzak eriÅŸimi korur.

Jit.io'nun 7 ipucu:
- GiriÅŸ doÄŸrulama ve Ã§Ä±kÄ±ÅŸ sanitizasyonu (Rebuff gibi araÃ§larla).
- Yetki kÄ±sÄ±tlamasÄ± ve izolasyon (en az yetki ilkesi).
- Kod ve baÄŸÄ±mlÄ±lÄ±k taramasÄ± (Semgrep, Jit ajanlarÄ±).
- UÃ§tan uca ÅŸifreleme (TLS 1.3, AES-256).
- DavranÄ±ÅŸ izleme ve rate limiting (OpenTelemetry).
- Just-in-Time gÃ¼venlik (dinamik eriÅŸim).
- GerÃ§ek zamanlÄ± yanÄ±t ve kurtarma (SIEM entegrasyonu).

Google Cloud'un katmanlÄ± yaklaÅŸÄ±mÄ±: Kimlik doÄŸrulama, yetkilendirme, denetlenebilirlik ve gÃ¼venli geliÅŸtirme ile geleneksel; guard modelleri ve adversè¨“ç·´ ile AI'ye Ã¶zgÃ¼.

A2AS Ã‡erÃ§evesi: BASIC modeli (Behavior Certificates, Authenticated Prompts, Security Boundaries, In-Context Defenses, Codified Policies) ile ajan gÃ¼venliÄŸini saÄŸlar; baÄŸlam penceresinde Ã§alÄ±ÅŸÄ±r, prompt enjeksiyonunu Ã¶nler.

OWASP TabanlÄ± Kontrol Listesi: 15 kategoride 163 Ã¶ÄŸe; AI yÃ¶netiÅŸimi, gÃ¼venli tasarÄ±m, prompt gÃ¼venliÄŸi, ajan aracÄ± gÃ¼venliÄŸi gibi alanlar kapsar.

### En Ä°yi Uygulamalar ve Ã‡erÃ§eveler
- **Guard Modelleri**: YÃ¼ksek etkili eylemleri denetler.
- **Advers EÄŸitim**: SimÃ¼le saldÄ±rÄ±larla dayanÄ±klÄ±lÄ±k artÄ±rÄ±lÄ±r.
- **SLSA Ã‡erÃ§evesi**: YazÄ±lÄ±m tedarik zinciri gÃ¼venliÄŸi iÃ§in SBOM ile kullanÄ±lÄ±r.
- **A2A ProtokolÃ¼**: Ajanlar arasÄ± iletiÅŸimde sandboxing ve giriÅŸ sanitizasyonu.
- **MCP GÃ¼venliÄŸi**: AraÃ§ zehirlenmesi tarayÄ±cÄ±larÄ± ve checklist'ler.

TÃ¼rkÃ§e baÄŸlamda, IBM GÃ¼venlik DoÄŸrulama AI AjanÄ± gibi entegrasyonlar, otomasyon ve zeki karar alma iÃ§in vurgulanÄ±r; yapay zeka siber gÃ¼venlik teknolojilerini ÅŸekillendirirken, log toplama ve regex gibi protokoller entegre edilir.

### Risk ve Savunma Tablosu

| Tehdit TÃ¼rÃ¼ | AÃ§Ä±klama | Savunma Stratejisi | Kaynak |
|-------------|----------|---------------------|--------|
| Prompt Enjeksiyonu | ZararlÄ± giriÅŸlerle ajan manipÃ¼lasyonu | GiriÅŸ sanitizasyonu, guard modelleri | , , [post:28] |
| Veri Zehirlenmesi | EÄŸitim verilerine mÃ¼dahale | Veri bÃ¼tÃ¼nlÃ¼ÄŸÃ¼ doÄŸrulamasÄ±, diferansiyel gizlilik | ,  |
| AraÃ§ Zehirlenmesi | AraÃ§ tanÄ±mlarÄ±nda gizli talimatlar | TarayÄ±cÄ±lar ve beyaz listeler | [post:18],  |
| DoS SaldÄ±rÄ±larÄ± | Kaynak tÃ¼ketimi | Rate limiting, kaynak sÄ±nÄ±rlamalarÄ± | ,  |
| Gizlilik SÄ±zÄ±ntÄ±larÄ± | Hassas veri ifÅŸasÄ± | Åifreleme (FPETS, FHE) | ,  |
| Ajan-Ajan Enfeksiyonu | Ã‡ok ajanlÄ± sistemlerde bulaÅŸma | A2AS gibi protokoller | , [post:22] |

### Gelecek YÃ¶nelimler
AI ajan gÃ¼venliÄŸi, standartlaÅŸma (A2AS gibi) ve blockchain entegrasyonuyla evrilir; Ã¶rneÄŸin, Theoriq protokolÃ¼ katkÄ± kanÄ±tÄ± ve ceza mekanizmalarÄ±yla gÃ¼ven saÄŸlar. Ã‡ok ajanlÄ± sistemlerde (multi-agent AI), daÄŸÄ±tÄ±lmÄ±ÅŸ yapÄ± gÃ¼venlik artÄ±rÄ±r. Ancak, token kullanÄ±m yÃ¼kÃ¼ ve model sapmalarÄ± gibi sÄ±nÄ±rlamalar devam eder.

Bu inceleme, AI ajanlarÄ±nÄ±n dengeli kullanÄ±mÄ±nÄ± teÅŸvik eder; riskler yÃ¶netilebilir olsa da, sÃ¼rekli izleme ve gÃ¼ncelleme ÅŸarttÄ±r.

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

---


