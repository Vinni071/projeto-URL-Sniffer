from scapy.all import sniff, conf
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS
import datetime


start_times_http = {}


start_time_https = None

def packet_callback(packet):
    global start_times_http, start_time_https
    
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        if packet[HTTPRequest].Host.decode() not in start_times_http:
            start_times_http[packet[HTTPRequest].Host.decode()] = datetime.datetime.now()
        else:
            end_time = datetime.datetime.now()
            start_time = start_times_http.pop(packet[HTTPRequest].Host.decode())
            time_spent = end_time - start_time
            print(f"URL Capturada (HTTP): {url}, Tempo gasto: {time_spent}")
            start_times_http[packet[HTTPRequest].Host.decode()] = end_time
    elif packet.haslayer(TLS):
       
        if start_time_https is None:
            start_time_https = datetime.datetime.now()
        else:
            end_time = datetime.datetime.now()
            time_spent = end_time - start_time_https
            print(f"Trafego HTTPS detectado, Tempo gasto: {time_spent}")
            start_time_https = end_time

print("Iniciando o sniffer...")
# Configura para usar a camada 3
conf.L3socket
sniff(prn=packet_callback, store=0, filter="tcp port 80 or tcp port 443")
