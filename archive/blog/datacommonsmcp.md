# Data Commons MCP: A New Way to Share Context with Language Models

**Kaynak:** Google Developers Blog[1](https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network)  
**Yayınlayan:** Google Developers

## Giriş

Google, dil modelleriyle daha etkili ve bağlamsal iletişim kurmak için **Model Context Protocol (MCP)** adlı yeni bir protokol tanıttı. Bu protokol, modellerin daha doğru ve güvenilir yanıtlar vermesini sağlamak için yapılandırılmış bağlam verilerini paylaşmayı mümkün kılıyor.

## MCP Nedir?

**Model Context Protocol**, bir dil modeline bağlam sağlayan JSON tabanlı bir veri yapısıdır. Bu bağlam:

- Kurumsal politikalar
- Teknik standartlar
- Kullanıcı tercihleri
- Gerçek zamanlı sistem durumu

gibi bilgileri içerebilir. MCP, bu bilgileri modele çalışma zamanında ileterek daha anlamlı ve bağlama uygun yanıtlar alınmasını sağlar.

## Data Commons ile Entegrasyon

Google, MCP'yi **Data Commons** ile entegre ederek kamuya açık verilerin dil modelleriyle daha etkili kullanılmasını sağlıyor. Örneğin:

- Bir şehirdeki nüfus verileri
- Eğitim düzeyi istatistikleri
- Ekonomik göstergeler

gibi veriler MCP aracılığıyla modele aktarılabilir ve model bu verileri analiz ederek daha doğru sonuçlar sunabilir.

## Kullanım Alanları

- **Eğitim:** Öğrencilerin seviyesine uygun yanıtlar üretme
- **Sağlık:** Klinik protokollere uygun öneriler sunma
- **Finans:** Şirket politikalarına göre risk analizi yapma
- **Yapay Zekâ Asistanları:** Kişiselleştirilmiş ve güvenilir yanıtlar üretme

## Teknik Detaylar

MCP, JSON formatında yapılandırılır ve aşağıdaki gibi bir örnek içerir:

```json
{
  "user_profile": {
    "location": "Karabük, Türkiye",
    "preferred_language": "Türkçe"
  },
  "organization_policies": {
    "data_retention": "30 days",
    "security_level": "high"
  }
}
```

## Sonuç

Google’ın MCP protokolü, dil modellerinin bağlamı daha iyi anlamasını sağlayarak daha güvenilir, kişiselleştirilmiş ve etkili yanıtlar üretmelerine olanak tanıyor. Bu, yapay zekâ ile etkileşimde yeni bir dönemin başlangıcı olabilir.