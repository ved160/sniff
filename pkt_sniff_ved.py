import sys

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore
import socket


init()
red = Fore.RED
yellow = Fore.YELLOW
blue = Fore.BLUE
green = Fore.GREEN


def sniff_packets(iface):
    if iface:
        sniff(filter = 'dst port 80' ,prn = process_pkt, iface = iface , store = False)
    else:
        sniff(prn = process_pkt, store=False)

def process_pkt(pkt):
    if pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dest_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dest_port = pkt[TCP].dport
        print(f"{blue}Source IP: {src_ip}  port : {src_port} Destination IP: {dest_ip} port : {dest_port}")
        
        
    if pkt.haslayer(HTTPRequest):
        url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
        method = pkt[HTTPRequest].Method.decode()
        print(f"{green} [+] {src_ip} is making HTTPrequest to {url} with method {method}")
        print("[+] HTTP DATA :")
        print(f"{yellow} {pkt[HTTPRequest].show()}")
        
        if pkt.haslayer(Raw):
            print(f"{red} [=] useful raw data : {pkt.getlayer(Raw).load.decode()}")

iface = sys.argv[1]
sniff_packets(iface)




