#!/usr/bin/python
############################################################
#Imports
from scapy.all import *
from netaddr import *
import sys
import threading
import binascii
import configparser
import argparse
import os

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False
# Disable default scapy output
conf.verb = 0

# Static Configuration
# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-c','--config-file', action='store', required=True, dest='config_file',help='[Required] DHCP Server configuration File.')
parser.add_argument('-i','--interface', action='store', required=True, dest='interface',help='[Required] Set interface to server DHCP services.')
parser.add_argument('-sub_int', required=False, action='store_true', help='[Optional] BringUp a subinterface with DHCP server address.')
parser.add_argument('-no_routing', required=False, action='store_true', help='[Optional] Disable automatic kernel routing enabler.')

args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config_file)
localiface = args.interface
localmac = get_if_hwaddr(localiface)

server_ip = config.get("dhcp-server-config", "server_ip")
dhcp_pool = config.get("dhcp-server-config", "dhcp_pool")
dhcp_subnet = config.get("dhcp-server-config", "dhcp_subnet")
dhcp_gateway = config.get("dhcp-server-config", "dhcp_dns")
dhcp_dns = config.get("dhcp-server-config", "server_ip")
dhcp_mask = config.get("dhcp-server-config", "dhcp_mask")
dhcp_domain = config.get("dhcp-server-config", "dhcp_domain")
dhcp_broadcast = config.get("dhcp-server-config", "dhcp_broadcast")
dhcp_netbiosserver = config.get("dhcp-server-config", "dhcp_netbiosserver")
dhcp_leasetime = config.get("dhcp-server-config", "dhcp_leasetime")

ip_forward = '/proc/sys/net/ipv4/ip_forward'


# Header
print ('###[ DHCP Server ]###')
print ('###[ Version 0.5 ]###')
print ('###[ Date 11/04/2040 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

#Static
x = dhcp_pool.find("-")
ip_pool = list(iter_iprange(dhcp_pool[0:x],dhcp_pool[x+1:]))
dhcp_pool_manager = iter(ip_pool)
dhcp_db = []

def enable_packet_forwarding():
    with open(ip_forward, 'w') as fd:
        fd.write('1')

def disable_packet_forwarding():
    with open(ip_forward, 'w') as fd:
        fd.write('0')

def dhcp_poll_next ():
    try:
        return str(dhcp_pool_manager.next())
    except StopIteration:
        return 'empty'

def returnIP(mac):
    ip = 'null'
    for row in dhcp_db:
        if row[0] == mac:
            ip = row[1]
            print ('###[ IP ja em cache : ' + mac + ' ' + ip + ' ]###')
    if ip == 'null':
        ip = dhcp_poll_next()
        print ('###[ IP novo alocado : ' + mac + ' ' + ip + ' ]###')
        if ip != 'empty':
            dhcp_db.append([mac,ip])
    return ip

def find_dhcp_traffic():
    sniff(filter="udp and (port 67 or 68)", prn=create_dhcp_packet_analyser, iface=localiface)

def create_dhcp_packet_analyser(packet):
    chield = threading.Thread(target=dhcp_packet_analyser, args=(packet,))
    chield.daemon = True
    chield.start()

def dhcp_packet_analyser(packet):
    if ((packet[Ether].dst == 'ff:ff:ff:ff:ff:ff') or (packet[Ether].dst == localmac)):
        if packet[DHCP]:
            if packet[DHCP].options:
                if packet[DHCP].options[0][1] == 1:
                    print('###[ DHCP Discovery Packet ]###')
                    print ('###[ Client MAC Address: ' + packet[DHCP].client_id + ']###')
                    client_ip = str(returnIP(packet[Ether].src))
                    if client_ip == 'empty':
                        print('###[ No more address Avaliable ]###')
                        return         
                    mac_addr_pkt = packet[Ether].src
                    raw_mac_addr_pkt = binascii.unhexlify(mac_addr_pkt.replace(":", ""))
                    mac_client_id = packet[DHCP].client_id
                    raw_mac_client_id = binascii.unhexlify(mac_client_id.replace(":", ""))
                    etthernet=Ether(src=localmac,dst=mac_addr_pkt)
                    ip=IP(src=server_ip,dst=client_ip)
                    udp=UDP(sport=67,dport=68)
                    bootp=BOOTP(op=2,yiaddr=client_ip,siaddr=server_ip,giaddr='0.0.0.0',chaddr=raw_mac_client_id,xid=packet[BOOTP].xid)
                    dhcp=DHCP(options=[('message-type','offer'),
                        ('server_id',server_ip),
                        ('lease_time',dhcp_leasetime),
                        ('subnet_mask',dhcp_mask),
                        ('domain',dhcp_domain),
                        ('router', dhcp_gateway),
                        ('name_server',dhcp_dns),
                        ('NetBIOS_server',dhcp_netbiosserver),
                        ('end')])
                    packet_Offer=etthernet/ip/udp/bootp/dhcp
                    print ('###[ packet DHCP Offer sended ]###')
                    print ('###[ ' + packet_Offer.summary() + ' ]###')
                    #print packet_Offer.summary()
                    #print packet_Offer.display()
                    #x = sendp(packet_Offer)
                    #print (packet_Offer)
                    print ('')
                if packet[DHCP].options[0][1] == 3:
                    mac_addr = packet[Ether].src
                    raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))
                    print ('###[ Find packet DHCP Request packet ]###')
                    print ('###[ Client MAC Address: ' + packet[Ether].src + ']###')
                    client_ip = returnIP(mac_addr)
                    if client_ip == 'empty':
                        print ('###[ No more address Avaliable ]###/n')
                    #print packet.summary()
                    #print packet.display()
                    etthernet=Ether(src=localmac,dst=packet[Ether].src)
                    ip=IP(src=server_ip,dst=client_ip)
                    udp=UDP(sport=67,dport=68)
                    bootp=BOOTP(op=2,yiaddr=client_ip,siaddr=server_ip,giaddr='0.0.0.0',chaddr=raw_mac,xid=packet[BOOTP].xid)
                    dhcp=DHCP(options=[('message-type','ack'),
                        ('server_id',server_ip),
                        ('lease_time',dhcp_leasetime),
                        ('subnet_mask',dhcp_mask),
                        ('domain',dhcp_domain),
                        ('broadcast_address', dhcp_broadcast),
                        ('router', dhcp_gateway),
                        ('name_server',dhcp_dns),
                        ('NetBIOS_server',dhcp_netbiosserver),
                        ('end')])
                    packet_ACK=etthernet/ip/udp/bootp/dhcp
                    print ('###[ DHCP Offer ACK Details ]###')
                    print ('###[ DHCP Offer ACK Details ]###')
                    print ('###[ ' + packet_ACK.summary() + ' ]###')
                    #print packet_ACK.display()
                    sendp(packet_ACK)
                    print ('')

# Kernel Routing
if args.no_routing:
    print ('###[ Ignore Kernel Routing disabled ]###')
    print ('')
else:
    print ('###[ Enable Kernel Routing enabling ]###')
    print ('###[ echo 1 > /proc/sys/net/ipv4/ip_forward ]###')
    enable_packet_forwarding()
    print ('')

# Sub Interface
if args.sub_int:
    print ('###[ No setup sub interface ]###')
    print ('')
else:
    print ('###[ Up sub interface ]###')
    localiface = localiface + ':0'
    cmd = ('ifconfig ' + localiface + ' up ' +  server_ip + ' netmask ' + dhcp_mask)
    print ('###[ ' + cmd + ' ]###')
    os.system(cmd)
    localmac = get_if_hwaddr(localiface)
    print ('')

try:
    find_dhcp_traffic()
except KeyboardInterrupt:
    pass
if not args.no_routing:
    print ('###[  Disable Kernel Routing enabling ]###')
    disable_packet_forwarding()
if not args.sub_int:
    print('###[  Shutdown sub interface ]###')
    cmd = ('ifconfig ' + localiface + ' down')
    os.system(cmd)



