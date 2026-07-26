#!/usr/bin/env python3
"""
NetScan - Asenkron Ağ Port ve Servis Tarayıcı CLI Aracı
"""

import argparse
import asyncio
import ipaddress
import json
import re
import socket
import sys
import time
from typing import List, Tuple, Optional, Dict, Any
from tabulate import tabulate


# --- Bilinen Varsayılan Servis Portları ---
KNOWN_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    27017: "MongoDB"
}


# --- IP ve Port Girdi Çözümleyiciler ---
def parse_ip_targets(target_str: str) -> List[str]:
    """
    Tek IP, IP Aralığı (192.168.1.1-10) veya CIDR (192.168.1.0/24) girdilerini çözer.
    """
    target_str = target_str.strip()
    
    # CIDR Kontrolü (Örn: 192.168.1.0/24)
    if "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError as e:
            raise ValueError(f"Geçersiz CIDR formatı '{target_str}': {e}")

    # IP Aralığı Kontrolü (Örn: 192.168.1.1-10)
    range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target_str)
    if range_match:
        base_ip = range_match.group(1)
        start_host = int(range_match.group(2))
        end_host = int(range_match.group(3))

        if start_host > end_host or start_host < 0 or end_host > 255:
            raise ValueError(f"Geçersiz IP aralığı sınırı: {target_str}")

        return [f"{base_ip}{i}" for i in range(start_host, end_host + 1)]

    # Tek IP Kontrolü
    try:
        ip_obj = ipaddress.ip_address(target_str)
        return [str(ip_obj)]
    except ValueError:
        raise ValueError(f"Geçersiz IP adresi formatı: '{target_str}'")


def parse_port_targets(port_str: str) -> List[int]:
    """
    Tek port (80), Port Aralığı (1-1000) veya Virgülle Ayrılmış Liste (22,80,443) çözer.
    """
    ports = set()
    port_str = port_str.strip()

    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start_p, end_p = map(int, part.split("-"))
                if start_p < 1 or end_p > 65535 or start_p > end_p:
                    raise ValueError
                ports.update(range(start_p, end_p + 1))
            except ValueError:
                raise ValueError(f"Geçersiz port aralığı: '{part}'")
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError
                ports.add(p)
            except ValueError:
                raise ValueError(f"Geçersiz port değeri: '{part}'")

    return sorted(list(ports))


# --- Tarama ve Banner Grabbing Mantığı ---
async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> str:
    """
    Açık porta bağlandıktan sonra banner bilgisi çeker veya HTTP isteği gönderir.
    """
    banner = ""
    try:
        # Önce gelen veriyi dinle (Örn: SSH, FTP bağlantıda banner gönderir)
        banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        banner = banner_bytes.decode('utf-8', errors='ignore').strip()
    except asyncio.TimeoutError:
        # Sunucu ilk veri göndermediyse HTTP HEAD isteği dene
        try:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: NetScan/1.0\r\n\r\n")
            await writer.drain()
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = banner_bytes.decode('utf-8', errors='ignore').strip()
        except Exception:
            banner = ""
    except Exception:
        banner = ""

    # Banner verisini temizle ve tek satıra indir
    if banner:
        first_line = banner.splitlines()[0]
        return first_line[:80]  # Maksimum 80 karakter
    return "Unknown / No Banner"


async def scan_port(
    semaphore: asyncio.Semaphore, 
    ip: str, 
    port: int, 
    timeout: float
) -> Optional[Dict[str, Any]]:
    """
    Belirtilen IP ve port için asenkron soket taraması yapar.
    """
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            # Bağlantı başarılı, Banner Tespiti Yap
            banner = await grab_banner(reader, writer, timeout=0.8)
            
            # Bağlantıyı kapat
            writer.close()
            await writer.wait_closed()

            service_hint = KNOWN_SERVICES.get(port, "Unknown")

            return {
                "ip": ip,
                "port": port,
                "status": "OPEN",
                "service": service_hint,
                "banner": banner
            }

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port kapalı, zaman aşımı veya erişilemiyor
            return None
        except Exception as e:
            # Diğer beklenmeyen hataları yut, taramayı kesme
            return None


# --- Ana Çalıştırıcı ---
async def run_scanner(
    targets: List[str], 
    ports: List[int], 
    concurrency: int, 
    timeout: float
) -> List[Dict[str, Any]]:
    """
    Tüm hedefleri verilen eşzamanlılık sınırı ile asenkron olarak tarar.
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []

    for ip in targets:
        for port in ports:
            tasks.append(scan_port(semaphore, ip, port, timeout))

    results = await asyncio.gather(*tasks)
    
    # Sadece açık olan (None olmayan) sonuçları filtrele
    open_results = [r for r in results if r is not None]
    return open_results


# --- Raporlama ve Çıktı ---
def print_table_results(results: List[Dict[str, Any]]) -> None:
    """
    Sonuçları terminalde düzenli bir tablo olarak gösterir.
    """
    if not results:
        print("\n[!] Açık port bulunamadı.")
        return

    table_data = []
    for r in results:
        table_data.append([r["ip"], r["port"], r["status"], r["service"], r["banner"]])

    headers = ["IP Adresi", "Port", "Durum", "Tahmini Servis", "Banner / Yanıt"]
    print("\n" + tabulate(table_data, headers=headers, tablefmt="fancy_grid"))


def export_json(results: List[Dict[str, Any]], filename: str) -> None:
    """
    Sonuçları JSON formatında kaydeder.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n[+] Sonuçlar başarıyla JSON olarak kaydedildi: {filename}")
    except IOError as e:
        print(f"\n[-] JSON dosyası yazılırken hata oluştu: {e}")


def export_txt(results: List[Dict[str, Any]], filename: str) -> None:
    """
    Sonuçları düz metin (TXT) formatında kaydeder.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("NetScan Tarama Sonuçları\n")
            f.write("=" * 50 + "\n\n")
            for r in results:
                f.write(f"IP: {r['ip']} | Port: {r['port']} | Servis: {r['service']} | Banner: {r['banner']}\n")
        print(f"\n[+] Sonuçlar başarıyla TXT olarak kaydedildi: {filename}")
    except IOError as e:
        print(f"\n[-] TXT dosyası yazılırken hata oluştu: {e}")


# --- CLI Giriş Noktası ---
def main():
    parser = argparse.ArgumentParser(
        description="NetScan - Asenkron Ağ Port ve Servis Tarayıcı CLI Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanımlar:
  python netscan.py -t 192.168.1.1 -p 80,443,22
  python netscan.py -t 192.168.1.1-10 -p 1-1024 -c 500
  python netscan.py -t 10.0.0.0/24 -p 21,22,80,443 --json output.json
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Hedef IP, IP Aralığı (192.168.1.1-10) veya CIDR (192.168.1.0/24)")
    parser.add_argument("-p", "--port", required=True, help="Hedef Port, Port Aralığı (1-1000) veya Liste (22,80,443)")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="Eşzamanlı istek sayısı (Default: 200)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Bağlantı zaman aşımı süresi saniye (Default: 1.5)")
    parser.add_argument("--json", type=str, help="Sonuçları JSON dosyası olarak kaydet")
    parser.add_argument("--txt", type=str, help="Sonuçları TXT dosyası olarak kaydet")

    args = parser.parse_args()

    # Girdileri Çözümle
    try:
        targets = parse_ip_targets(args.target)
        ports = parse_port_targets(args.port)
    except ValueError as e:
        print(f"[-] Girdi Hata Bilgisi: {e}")
        sys.exit(1)

    total_checks = len(targets) * len(ports)
    print(f"[*] Tarama Başlatılıyor...")
    print(f"[*] Toplam Hedef IP  : {len(targets)}")
    print(f"[*] Toplam Port Sayısı: {len(ports)}")
    print(f"[*] Toplam Kontrol    : {total_checks} istek")
    print(f"[*] Eşzamanlılık Limit: {args.concurrency}")
    print(f"[*] Zaman Aşımı       : {args.timeout} saniye\n")

    start_time = time.time()

    # Asenkron Taramayı Çalıştır
    try:
        results = asyncio.run(
            run_scanner(targets, ports, args.concurrency, args.timeout)
        )
    except KeyboardInterrupt:
        print("\n[!] Tarama kullanıcı tarafından iptal edildi.")
        sys.exit(0)

    elapsed = time.time() - start_time

    # Ekrana Yazdır
    print_table_results(results)
    print(f"\n[*] Tarama {elapsed:.2f} saniyede tamamlandı.")

    # Dosyalara Kaydet
    if args.json:
        export_json(results, args.json)
        
    if args.txt:
        export_txt(results, args.txt)


if __name__ == "__main__":
    main()
