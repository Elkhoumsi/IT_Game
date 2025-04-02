from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from collections import defaultdict
import geoip2.database
import csv
import json
import requests
import re
import threading

# Configurer l'API VirusTotal
VIRUSTOTAL_API_KEY = "d48838f84447e4067be72d125fe0493501d95004dc84e0fee74f708de17a993c"  # Remplacez par votre clé API VirusTotal
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/urls"

# Charger le fichier PCAP
pcap_file = "chall_wshark7.pcap"  # Remplace par ton fichier    
packets = rdpcap(pcap_file)

# Dictionnaires pour stocker les informations
ip_counter = defaultdict(int)
port_counter = defaultdict(int)
icmp_counter = defaultdict(int)
brute_force_attempts = defaultdict(int)
suspicious_ips = []
arp_requests = defaultdict(int)
dns_queries = defaultdict(int)
fast_flux_ips = defaultdict(list)
downloaded_files = []
malicious_downloads = []

# Extensions de fichiers suspects
suspicious_extensions = [".exe", ".zip", ".rar", ".bat", ".cmd", ".vbs", ".js", ".dll", ".scr"]

# Charger la base de données GeoIP
geoip_db = "GeoLite2-Country.mmdb"
try:
    reader = geoip2.database.Reader(geoip_db)
    print("Base de données GeoIP chargée avec succès !")
except Exception as e:
    print(f"Erreur lors du chargement de la base GeoIP : {e}")
    exit()

def get_country(ip):
    try:
        response = reader.country(ip)
        return response.country.name
    except geoip2.errors.AddressNotFoundError:
        return "IP inconnue dans GeoIP"
    except Exception as e:
        return "Erreur"

def check_ip_on_virustotal(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"{VIRUSTOTAL_URL}{ip}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                return data["data"]["attributes"]["last_analysis_stats"]
    except:
        return None

def check_url_on_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"url": url}
    try:
        response = requests.post(VIRUSTOTAL_FILE_URL, headers=headers, data=data)
        if response.status_code == 200:
            return response.json()
    except:
        return None

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_counter[src_ip] += 1
        
        if packet.haslayer(ICMP):
            icmp_counter[src_ip] += 1
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            
            if dst_port in [22, 23, 3389, 80, 443]:
                port_counter[(src_ip, dst_port)] += 1
                if port_counter[(src_ip, dst_port)] > 5:
                    brute_force_attempts[src_ip] += 1
    
    if packet.haslayer(ARP) and packet[ARP].op == 1:
        arp_requests[packet[ARP].psrc] += 1
    
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        dns_queries[packet[IP].src] += 1
        fast_flux_ips[packet[IP].src].append(packet[DNS].qd.qname.decode())
    
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        urls = re.findall(r'(https?://\S+)', payload)
        for url in urls:
            if any(ext in url for ext in suspicious_extensions):
                downloaded_files.append((packet[IP].src, url))
                result = check_url_on_virustotal(url)
                if result and "malicious" in result:
                    malicious_downloads.append((packet[IP].src, url))

threads = []
for packet in packets:
    thread = threading.Thread(target=analyze_packet, args=(packet,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

# Détection des comportements suspects
for ip, count in ip_counter.items():
    if count > 100:
        suspicious_ips.append((ip, "Volume élevé de paquets"))
for ip, count in icmp_counter.items():
    if count > 50:
        suspicious_ips.append((ip, "Volume élevé de paquets ICMP"))
for (ip, port), count in port_counter.items():
    if count > 10:
        suspicious_ips.append((ip, f"Scan de ports sur le port {port}"))
for ip, attempts in brute_force_attempts.items():
    if attempts > 3:
        suspicious_ips.append((ip, "Attaque par force brute"))
for ip, count in arp_requests.items():
    if count > 20:
        suspicious_ips.append((ip, "Potentielle attaque ARP Spoofing"))
for ip, count in dns_queries.items():
    if count > 30:
        suspicious_ips.append((ip, "Possibilité de DNS Tunneling"))
for ip, url in malicious_downloads:
    suspicious_ips.append((ip, f"Téléchargement de fichier malveillant: {url}"))

# Génération des fichiers de sortie

# 1️⃣ **Fichier des téléchargements suspects (suspicious_downloads.csv)**
suspicious_downloads_filename = "suspicious_downloads.csv"
with open(suspicious_downloads_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Source IP", "Fichier téléchargé"])
    writer.writerows(downloaded_files)

# 2️⃣ **Fichier des résultats VirusTotal (virustotal_results.csv)**
virustotal_results_filename = "virustotal_results.csv"
virustotal_results = []
for url in downloaded_files:
    result = check_url_on_virustotal(url[1])
    if result:
        malicious_count = result.get("malicious", 0)
        harmless_count = result.get("harmless", 0)
        suspicious_count = result.get("suspicious", 0)
        undetected_count = result.get("undetected", 0)
        virustotal_results.append([url[1], malicious_count, harmless_count, suspicious_count, undetected_count])

with open(virustotal_results_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["URL", "Malicious", "Harmless", "Suspicious", "Undetected"])
    writer.writerows(virustotal_results)

# 3️⃣ **Fichier des IPs malveillantes (malicious_ips.json)**
malicious_ips = [ip for ip, reason in suspicious_ips if "malveillant" in reason.lower()]
malicious_ips_filename = "malicious_ips.json"
with open(malicious_ips_filename, "w", encoding="utf-8") as jsonfile:
    json.dump(malicious_ips, jsonfile, indent=4)

# 4️⃣ **Fichier des IPs suspectes (suspicious_ips.csv)**
suspicious_ips_filename = "suspicious_ips.csv"
with open(suspicious_ips_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["IP Suspecte", "Pays", "Raison"])
    for ip, reason in suspicious_ips:
        country = get_country(ip)  # Obtenir le pays de l'IP à l'aide de la fonction GeoIP
        writer.writerow([ip, country, reason])

print("Fichiers générés avec succès :")
print("   - 📄 suspicious_downloads.csv (Téléchargements suspects)")
print("   - 📄 virustotal_results.csv (Résultats VirusTotal)")
print("   - 📄 malicious_ips.json (IPs malveillantes en JSON)")
print("   - 📄 suspicious_ips.csv (IPs suspectes avec raisons et pays)") 