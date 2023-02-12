from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore
import socket


init()
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN


def sniff_packets(iface):
    if iface:
        sniff(prn = process_pkt, iface = iface , store = False)
    else:
        sniff(prn = process_pkt, store=False)

def process_pkt(pkt):
    if pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dest_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dest_port = pkt[TCP].dport
        print(f"{green}Source IP: {src_ip}  port : {src_port} Destination IP: {dest_ip} port : {dest_port}")

sniff_packets("eth0")




