from scapy.all import sniff, conf, Raw, TCP
from scapy.layers.http import HTTPRequest
import datetime
import struct


start_times_http = {}
start_times_https = {}


def extract_sni(raw_bytes):
    """Extrai o SNI (Server Name Indication) dos bytes brutos de um TLS ClientHello."""
    try:
        # TLS Record: tipo 0x16 (Handshake), versão (2 bytes), tamanho (2 bytes)
        if len(raw_bytes) < 5 or raw_bytes[0] != 0x16:
            return None

        # Handshake: tipo 0x01 (ClientHello)
        handshake_type = raw_bytes[5]
        if handshake_type != 0x01:
            return None

        # Pular até as extensões do ClientHello
        # TLS Record Header (5) + Handshake Header (4) + Client Version (2) + Random (32)
        offset = 5 + 4 + 2 + 32

        # Session ID length
        if offset >= len(raw_bytes):
            return None
        session_id_len = raw_bytes[offset]
        offset += 1 + session_id_len

        # Cipher Suites length (2 bytes)
        if offset + 2 > len(raw_bytes):
            return None
        cipher_suites_len = struct.unpack('!H', raw_bytes[offset:offset+2])[0]
        offset += 2 + cipher_suites_len

        # Compression Methods length (1 byte)
        if offset >= len(raw_bytes):
            return None
        compression_len = raw_bytes[offset]
        offset += 1 + compression_len

        # Extensions length (2 bytes)
        if offset + 2 > len(raw_bytes):
            return None
        extensions_len = struct.unpack('!H', raw_bytes[offset:offset+2])[0]
        offset += 2

        # Iterar pelas extensões
        extensions_end = offset + extensions_len
        while offset + 4 <= extensions_end and offset + 4 <= len(raw_bytes):
            ext_type = struct.unpack('!H', raw_bytes[offset:offset+2])[0]
            ext_len = struct.unpack('!H', raw_bytes[offset+2:offset+4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                if offset + 5 <= len(raw_bytes):
                    # SNI list length (2 bytes) + type (1 byte) + name length (2 bytes)
                    sni_list_len = struct.unpack('!H', raw_bytes[offset:offset+2])[0]
                    sni_type = raw_bytes[offset+2]
                    sni_len = struct.unpack('!H', raw_bytes[offset+3:offset+5])[0]
                    if sni_type == 0x00 and offset + 5 + sni_len <= len(raw_bytes):
                        return raw_bytes[offset+5:offset+5+sni_len].decode('utf-8', 'ignore')
                return None

            offset += ext_len

    except Exception:
        pass
    return None


def packet_callback(packet):
    global start_times_http, start_times_https

    # Captura HTTP
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode('utf-8', 'ignore') if packet[HTTPRequest].Host else ""
        path = packet[HTTPRequest].Path.decode('utf-8', 'ignore') if packet[HTTPRequest].Path else ""
        url = f"http://{host}{path}"
        if host not in start_times_http:
            start_times_http[host] = datetime.datetime.now()
        else:
            end_time = datetime.datetime.now()
            start_time = start_times_http.pop(host)
            time_spent = end_time - start_time
            print(f"URL Capturada (HTTP): {url}, Tempo gasto: {time_spent}", flush=True)
            start_times_http[host] = end_time

    # Captura HTTPS via SNI do TLS ClientHello (bytes brutos)
    elif packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        sni = extract_sni(payload)
        if sni:
            url = f"https://{sni}"
            if sni not in start_times_https:
                start_times_https[sni] = datetime.datetime.now()
                print(f"URL Capturada (HTTPS): {url}", flush=True)
            else:
                end_time = datetime.datetime.now()
                start_time = start_times_https.pop(sni)
                time_spent = end_time - start_time
                print(f"URL Capturada (HTTPS): {url}, Tempo gasto: {time_spent}", flush=True)
                start_times_https[sni] = end_time


print("Iniciando o sniffer...")
conf.L3socket
sniff(prn=packet_callback, store=0, filter="tcp port 80 or tcp port 443")
