# NetScan - Asenkron Ağ Port ve Servis Tarayıcı

NetScan, harici bağımlılıklara (nmap vb.) ihtiyaç duymadan, doğrudan soket seviyesinde yüksek performanslı asenkron port taraması ve banner tespiti yapan modern bir CLI aracıdır.

## Özellikler

- **Esnek IP Tanımlama:** Tek IP (`192.168.1.1`), IP Aralığı (`192.168.1.1-10`) ve CIDR blokları (`192.168.1.0/24`).
- **Esnek Port Tanımlama:** Tek Port (`80`), Port Aralığı (`1-1000`) veya Liste (`22,80,443`).
- **Yüksek Eşzamanlılık:** `asyncio` ve semafor mekanizması ile binlerce portu saniyeler içinde tarar.
- **Servis & Banner Tespiti:** Bağlantı kurulan açık portların banner bilgilerini okuyarak servisi belirlemeye çalışır.
- **Çıktı Seçenekleri:** Şık terminal tablosu, `JSON` ve `TXT` dosya formatı desteği.

## Kurulum

1. Repoyu klonlayın:
   ```bash
   git clone [https://github.com/KULLANICI_ADI/network-port-scanner.git](https://github.com/KULLANICI_ADI/network-port-scanner.git)
   cd network-port-scanner
## Lisans
Bu proje [MIT](LICENSE) lisansı altında lisanslanmıştır.
