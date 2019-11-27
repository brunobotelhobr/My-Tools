#!/usr/bin/python

#Imports
from scapy.all import *
from termcolor import colored
import datetime
import string
import argparse
import platform
import binascii

# Static Configuration
# Default Broadcast MAC Address
broadcast_mac = 'ff:ff:ff:ff:ff:ff'
# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False
# Disable default scapy output
conf.verb = 0

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i','--interface', action='store', required=True, dest='interface',help='Set interface to use')
args = parser.parse_args()

print(args.interface)
localiface = args.interface

# Configuration
localmac = get_if_hwaddr(localiface)

# Header
print ('###[ DHCP Discovery ]###')
print ('###[ Version 0.7 ]###')
print ('###[ Date 24/11/2019 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def log_timestamp():
    return colored(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 'grey')

def mac_to_hex(mac):
    if '3.' in platform.python_version():
        return binascii.unhexlify(mac.replace(':',''))
    else:
        return mac.replace(':', '').decode('hex')

localmac_raw = mac_to_hex(localmac)
print (localmac)
print (localmac_raw)

# Craft DHCP Discover
letters = string.ascii_lowercase
hostname = str(''.join(random.choice(letters) for i in range(10)))
ethernet = Ether(src=localmac,dst=broadcast_mac)
ip = IP(src="0.0.0.0", dst='255.255.255.255')
udp = UDP(sport=68,dport=67)
bootp = BOOTP(chaddr=localmac_raw,xid = RandInt())
dhcp = DHCP(options=[('message-type', 'discover'),
('param_req_list',[1, 121, 3, 6, 15, 119, 252, 44, 46]),
('max_dhcp_size', 1500),
('client_id', localmac),
('lease_time', 43200),
('hostname', hostname),
'end'])
dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp

# Send discover, wait for reply
print ('###[ ' + log_timestamp() + ' Send discover, wait for reply ]###')
#print dhcp_discover_packet.summary()
#print dhcp_discover_packet.display()
print ('')
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
