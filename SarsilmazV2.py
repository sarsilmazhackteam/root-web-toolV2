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

# ASCII Sanatı
def display_ascii_art():
    metin = "Root"
    ascii_art = pyfiglet.figlet_format(metin)
    renkli_ascii = Fore.RED + ascii_art
    colorama.init()
    print(renkli_ascii)
    print(colored("t.me/sarsilmazhackteam", 'red'))

# Güvenli HTTP isteği
def safe_request(url, method='GET', data=None, files=None):
    try:
        if method == 'POST':
            response = requests.post(url, data=data, files=files, timeout=10)
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
        command = ["sqlmap", "-u", url, "--batch", "--dbs", "--output-dir=/tmp/sqlmap_output"]
        result = subprocess.run(command, capture_output=True, text=True)
        if "available databases" in result.stdout.lower():
            databases = []
            in_databases_section = False
            for line in result.stdout.splitlines():
                if "available databases" in line.lower():
                    in_databases_section = True
                    continue
                if in_databases_section:
                    if line.strip().startswith("[*]"):
                        continue
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
    test_url = f"{url}?search={payload}"
    response = safe_request(test_url)
    if payload in response.text:
        print(colored("[!] XSS açığı bulundu!", 'red'))
    else:
        print(colored("[+] XSS açığı bulunamadı.", 'green'))

# CSRF Testi
def test_csrf(url):
    headers = {'Origin': url}
    response = requests.post(url, headers=headers)
    if "forbidden" in response.text.lower():
        print(colored("[+] CSRF koruması var.", 'green'))
    else:
        print(colored("[!] CSRF açığı bulunabilir.", 'red'))

# Port Tarama
def scan_ports(host, ports=[80, 443, 8080, 21, 22, 3306]):
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((host, port))
        if result == 0:
            print(colored(f"[+] Port {port} açık.", 'green'))
        else:
            print(colored(f"[+] Port {port} kapalı.", 'red'))
        s.close()

# Dosya Yükleme Güvenlik Testi
def test_file_upload(url):
    files = {'file': ('test.php', '<?php echo "test"; ?>')}
    response = safe_request(url, method='POST', data=None, files=files)
    if "test" in response.text:
        print(colored("[!] Dosya yükleme açığı bulundu!", 'red'))
    else:
        print(colored("[+] Dosya yükleme açığı bulunamadı.", 'green'))

# WAF Tespiti
def detect_waf(url):
    response = safe_request(url)
    waf_signatures = ['cf-ray', 'x-robots-tag', 'server', 'x-waf']
    for signature in waf_signatures:
        if signature in response.headers:
            print(colored(f"[+] WAF tespit edildi: {signature}", 'yellow'))
            return True
    print(colored("[+] WAF tespit edilmedi.", 'green'))
    return False

# Tarama Fonksiyonu
def scan_url(url):
    print(colored(f"\n[+] {url} taranıyor...\n", 'yellow'))
    test_command_injection(url)
    test_open_directory(url)
    test_file_inclusion(url)
    detect_sql_database(url)
    test_xss(url)
    test_csrf(url)
    scan_ports(url.replace("https://", "").replace("http://", ""))
    test_file_upload(url)
    detect_waf(url)

# Ana Fonksiyon
def main():
    display_ascii_art()
    parser = argparse.ArgumentParser(description="Linux İçin Güvenli Web Zafiyeti Tarayıcı")
    parser.add_argument("url", help="Taranacak URL")
    args = parser.parse_args()

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print(colored("[!] Lütfen geçerli bir URL girin. (http:// veya https:// ile başlamalı)", 'red'))
        sys.exit(1)

    scan_url(args.url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] İşlem kullanıcı tarafından durduruldu.", 'red'))
        sys.exit(0)
