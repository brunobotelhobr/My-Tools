#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
############################################################

from scapy.all import *
from termcolor import colored
import datetime

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Configuration
localiface = 'eth0'
localmac = get_if_hwaddr(localiface)
localmacraw = localmac.replace(':','').decode('hex')
broadcast_mac = 'ff:ff:ff:ff:ff:ff'

# Header
print '###[ DHCP Discovery ]###'
print '###[ Version 0.3 ]###'
print '###[ Date 21/11/2019 ]###'
print '###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###'
print ''

def log_timestamp():
    return colored(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 'grey')

# Craft DHCP Discover
ethernet = Ether(src=localmac,dst=broadcast_mac)
ip = IP(src="0.0.0.0", dst='255.255.255.255')
udp = UDP(sport=68,dport=67)
bootp = BOOTP(chaddr=localmacraw,xid = RandInt())
dhcp = DHCP(options=[('message-type', 'discover'), 'end'])
dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp

# Send discover, wait for reply
print '###[ ' + log_timestamp() + ' Send discover, wait for reply ]###'
#print dhcp_discover_packet.summary()
#print dhcp_discover_packet.display()
print ''
dhcp_offer = srp1(dhcp_discover_packet,iface=localiface)

# Results
for pkt in dhcp_offer:
    print ('###[ ' + log_timestamp() + ' DHCP Server Address :' + colored (pkt.getlayer(BOOTP).siaddr,'red') + ' ]###')
    print ('###[ ' + log_timestamp() + ' Your Address :' + colored(pkt.getlayer(BOOTP).yiaddr,'blue') + ' ]###')
    print ('###[ ' + log_timestamp() + ' DHCP Parameters ] ###')
    for i in pkt.getlayer(DHCP).options:
        print (i[0] + ' : \t' + colored (i[1],'green'))
    print (' ')
    #print (pkt.summary())
    #print (pkt.display())
