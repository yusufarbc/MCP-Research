# Agentic AI: A New Frontier for Network Engineers

**Yazar:** Kareem Iskander  
**Yayın Tarihi:** 13 Mayıs 2025  
**Kaynak:** [Cisco Blogs](https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network)[1](https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network)

## Giriş

Yeni nesil ağ mühendisliği, **Agentic AI** ile şekilleniyor. Bu yapay zekâ, ağınızı anlayan, yapılandıran, sorun gideren ve tasarlayan bir yardımcıya dönüşüyor. Bunun temelinde ise **Model Context Protocol (MCP)** yer alıyor.

## MCP Nedir?

**Model Context Protocol**, büyük dil modellerine (LLM) ağınızla ilgili yapılandırılmış bilgileri çalışma zamanında otomatik olarak aktarmanızı sağlar. Bu sayede:

- Ağ cihazlarınız
- Kullandığınız standartlar
- Tercih ettiğiniz teknolojiler (örneğin OSPF > EIGRP)
- Değişiklik kontrol süreçleriniz

gibi bilgiler modele aktarılır ve daha doğru, bağlama uygun yanıtlar alınır.

## Gerçek Dünya Örneği

Bir LLM tabanlı ağ asistanı oluşturduğunuzu varsayalım. MCP ile aşağıdaki gibi bir JSON yapılandırması göndererek modelin bağlamı anlamasını sağlarsınız:

```json
{
  "network_standards": {
    "routing_protocols": ["OSPF", "BGP"],
    "preferred_encapsulation": "VXLAN",
    "security_policies": {
      "ssh_required": true,
      "telnet_disabled": true
    }
  },
  "topology": {
    "core_devices": ["core-sw1", "core-sw2"],
    "edge_devices": ["edge-fw1", "edge-fw2"],
    "site_layout": "hub and spoke"
  }
}
```

Bu bağlam sayesinde model, örneğin yeni bir site için yapılandırma üretirken ağınıza uygun yanıtlar verir.

## MCP Kullanmak İçin Gerekli Beceriler

- **API Temelleri:** JSON verilerini API üzerinden iletme
- **Ağ Metadatası Bilgisi:** Routing, VLAN, güvenlik gibi ağ bileşenlerini tanıma
- **Python Scripting:** Dinamik veri toplama ve MCP çağrıları oluşturma
- **LLM Temelleri:** Prompt ve bağlam penceresi mantığını anlama

## Uygulamalı Başlangıç

Cisco, GitHub üzerinden bir MCP sunucusu örneği sunuyor. Bu sunucu:

- Ağ standartlarını sunar
- Cihaz sağlığını raporlar
- Claude Desktop ile bağlantı kurarak AI asistanını ağınızla entegre eder

## Sonuç

Agentic AI ile ağ mühendisleri artık sadece otomasyon değil, bağlamlı otomasyon yapabiliyor. Bu teknoloji, ağ mühendisliğinde yeni bir çağın kapılarını aralıyor.