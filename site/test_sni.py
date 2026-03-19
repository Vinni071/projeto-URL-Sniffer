from scapy.all import sniff, conf
from scapy.layers.tls.all import TLS
from scapy.layers.tls.extensions import TLS_Ext_ServerName

def cb(p):
    if p.haslayer(TLS_Ext_ServerName):
        print("SNI:", p[TLS_Ext_ServerName].servernames[0].servername.decode())

print("Loaded")
