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

print("IPs suspectes détectées :")
data = []
for ip, reason in suspicious_ips:
    country = get_country(ip)
    print(f"{ip} ({country}) - Raison : {reason}")
    data.append({"IP": ip, "Pays": country, "Raison": reason})

csv_filename = "suspicious_ips.csv"
json_filename = "suspicious_ips.json"
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["IP Suspecte", "Pays", "Raison"])
    writer.writerows([[d["IP"], d["Pays"], d["Raison"]] for d in data])

with open(json_filename, "w", encoding="utf-8") as jsonfile:
    json.dump(data, jsonfile, indent=4)

print(f"Fichiers {csv_filename} et {json_filename} créés avec succès !")
reader.close()  
from collections import defaultdict
import geoip2.database
import csv
import requests
import json
import re

# Configurer l'API VirusTotal
VIRUSTOTAL_API_KEY = "d48838f84447e4067be72d125fe0493501d95004dc84e0fee74f708de17a993c"  # Remplace par ta clé
VIRUSTOTAL_URL_IP = "https://www.virustotal.com/api/v3/ip_addresses/"

# Charger le fichier PCAP
pcap_file = "chall_wshark7.pcap"  # Remplace par ton fichier
packets = rdpcap(pcap_file)

# Dictionnaires de suivi
downloads = []
suspicious_ips = set()
malicious_ips = []
virustotal_results = []

# Fonction pour vérifier une IP sur VirusTotal avec un filtre
def check_virustotal(ip):
    """ Vérifie une IP sur VirusTotal """
    url = VIRUSTOTAL_URL_IP + ip
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return last_analysis_stats
    except Exception as e:
        print(f"Erreur VirusTotal pour {ip}: {e}")
    return None

# Fonction pour filtrer et envoyer uniquement certaines IPs à VirusTotal
def send_filtered_ips_to_virustotal(ip_list):
    """ Envoie uniquement certaines IPs ayant téléchargé des fichiers suspects à VirusTotal """
    for ip in ip_list:
        # Filtrage : ignorer les IP privées (ex: 192.168.x.x, 10.x.x.x, 172.16.x.x)
        if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))", ip):
            print(f"⏭️ Ignoré (IP privée): {ip}")
            continue

        result = check_virustotal(ip)
        if result:
            malicious_count = result.get("malicious", 0)
            harmless_count = result.get("harmless", 0)
            suspicious_count = result.get("suspicious", 0)
            undetected_count = result.get("undetected", 0)
            
            virustotal_results.append([ip, malicious_count, harmless_count, suspicious_count, undetected_count])
            
            if malicious_count > 0:
                malicious_ips.append(ip)
                print(f"⚠️ IP malveillante détectée: {ip} (Malicious: {malicious_count})")
            else:
                print(f"✅ IP semble sûre: {ip}")

# Détection des téléchargements de fichiers
file_extensions = ["exe", "zip", "rar", "bat", "dll", "msi"]
for packet in packets:
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore").split("\r\n")
        for line in payload:
            match = re.search(r"GET\s+(/[^\s]+)\s+HTTP", line)
            if match:
                file_url = match.group(1)
                if any(file_url.endswith(ext) for ext in file_extensions):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    downloads.append([src_ip, dst_ip, file_url])
                    suspicious_ips.add(src_ip)

# Vérification des IPs ayant téléchargé des fichiers suspects
send_filtered_ips_to_virustotal(suspicious_ips)

# 📂 **Sauvegarde des résultats dans des fichiers bien organisés**
# 1️⃣ **Fichier des téléchargements suspects**
with open("suspicious_downloads.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Source IP", "Destination IP", "Fichier téléchargé"])
    writer.writerows(downloads)

# 2️⃣ **Fichier des IPs malveillantes détectées sur VirusTotal**
with open("virustotal_results.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["IP", "Malicious", "Harmless", "Suspicious", "Undetected"])
    for row in virustotal_results:
        writer.writerow(row)

# 3️⃣ **Fichier des IPs malveillantes (CSV)**
with open("malicious_ips.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Malicious IP"])  # Ajoute l'en-tête
    for ip in malicious_ips:
        writer.writerow([ip])


print("\n📂 **Analyse terminée !**")
print("✅ Résultats enregistrés dans :")
print("   - 📄 suspicious_downloads.csv (Téléchargements suspects)")
print("   - 📄 virustotal_results.csv (Résultats VirusTotal)")
print("   - 📄 malicious_ips.csv (IP malveillantes en CSV)")