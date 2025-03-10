# 1337 X Sarsılmaz

# 1337 X SARSILMAZ Web Güvenlik Tarayıcı - README

Bu araç **Emin Sarsılmaz** tarafından yapılmıştır ve **1337 Hack Team** ile **Sarsılmaz Hack Team** adı altında geliştirilmiştir.

## Genel Bakış
Sarsilmaz Web Güvenlik Tarayıcı, web uygulamalarındaki güvenlik açıklarını tespit etmek için kullanılan bir Python aracıdır.
Aşağıdaki güvenlik testlerini gerçekleştirir:
- SQL Enjeksiyonu
- Komut Enjeksiyonu
- Açık Dizin Tespiti
- Dosya Dahil Etme
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Port Tarama
- SSL/TLS güvenlik testleri

## Gereksinimler

### Python Kütüphaneleri
Aşağıdaki Python kütüphanelerini yüklemeniz gerekmektedir:
- requests
- beautifulsoup4
- termcolor
- pyfiglet
- colorama
- subprocess

Yüklemek için aşağıdaki komutu çalıştırabilirsiniz:

```bash
pip install requests beautifulsoup4 termcolor pyfiglet colorama
```

### Harici Araçlar
- **SQLMap**: Veritabanı tespiti için kullanılan bir araçtır. [SQLMap İndir](https://github.com/sqlmapproject/sqlmap)

## Kullanım
Python script'ini kullanmak için şu şekilde çalıştırabilirsiniz:

```bash
python SarsilmazV2.py http://example.com
```

Bu komut, belirtilen URL'yi tarar ve güvenlik açıklarını raporlar.

## Özellikler
- **Komut Enjeksiyonu**: Sisteme komut enjekte edilip edilemeyeceğini test eder.
- **Açık Dizin Tespiti**: Web uygulamanızda açık dizinlerin olup olmadığını kontrol eder.
- **Dosya Dahil Etme**: Web uygulamanızda dosya dahil etme (LFI/RFI) açığını test eder.
- **SQL Injection**: SQL enjeksiyonu test eder.
- **XSS (Cross-Site Scripting)**: XSS açığını tespit eder.
- **CSRF (Cross-Site Request Forgery)**: CSRF açığına karşı test yapar.
- **Port Tarama**: Sunucu portlarını tarar.
- **SSL/TLS Güvenlik**: SSL/TLS bağlantısının güvenliğini kontrol eder.

## License
Bu araç, sadece eğitim amaçlı kullanılmalıdır. Hedef sistemler üzerinde izin almadığınız sürece kullanmayın.
