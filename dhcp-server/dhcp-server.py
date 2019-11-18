#!/usr/bin/python
############################################################

from scapy.all import *
from netaddr import *
import sys
import threading
import binascii
import ConfigParser
import os

# Configuration
config = ConfigParser.ConfigParser()
config.read("dhcp-server.conf")

server_ip = config.get("dhcp-server-config", "server_ip")
localiface = config.get("dhcp-server-config", "localiface")
dhcp_pool = config.get("dhcp-server-config", "dhcp_pool")
dhcp_subnet = config.get("dhcp-server-config", "dhcp_subnet")
dhcp_gateway = config.get("dhcp-server-config", "dhcp_dns")
dhcp_dns = config.get("dhcp-server-config", "server_ip")
dhcp_mask = config.get("dhcp-server-config", "dhcp_mask")
dhcp_domain = config.get("dhcp-server-config", "dhcp_domain")
dhcp_broadcast = config.get("dhcp-server-config", "dhcp_broadcast")
dhcp_netbiosserver = config.get("dhcp-server-config", "dhcp_netbiosserver")
dhcp_leasetime = config.get("dhcp-server-config", "dhcp_leasetime")

#Enable Kernel Routing
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

# Bring Up interface
os.system("ifconfig " + localiface + ' ' + server_ip + ' netmask ' + dhcp_subnet + ' up')

#Retrive Local MAC Address
localmac = get_if_hwaddr(localiface)

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Header
print ('###[ DHCP Server ]###')
print ('###[ Version 0.4 ]###')
print ('###[ Date 18/11/2019 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

#Static
x = dhcp_pool.find("-")
ip_pool = list(iter_iprange(dhcp_pool[0:x],dhcp_pool[x+1:]))
dhcp_pool_manager = iter(ip_pool)
dhcp_db = []

def    dhco_poll_next ():
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
        ip =    dhco_poll_next ()
        print ('###[ IP novo alocado : ' + mac + ' ' + ip + ' ]###')
        if ip != 'empty':
            dhcp_db.append([mac,ip])
    return ip

def find_dhcp_traffic():
    sniff(filter='port 67 or port 68', prn=create_dhcp_packet_analyser, iface=localiface)

def create_dhcp_packet_analyser(packet):
    chield = threading.Thread(target=dhcp_packet_analyser, args=(packet,))
    chield.daemon = True
    chield.start()

def dhcp_packet_analyser(packet):
    if packet[DHCP]:
        if packet[DHCP].options:
            if packet[DHCP].options[0][1] == 1:
                print('###[ DHCP Discovery Packet ]###')
                print ('###[ Client MAC Address: ' + packet[Ether].src + ']###')
                #print packet.summary()
                #print packet.display()
                client_ip = str(returnIP(packet[Ether].src))
                if client_ip == 'empty':
                    print('###[ No more address Avaliable ]###')
                    return         
                mac_addr = packet[Ether].src
                raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))
                etthernet=Ether(src=localmac,dst=packet[Ether].src)
                ip=IP(src=server_ip,dst=client_ip)
                udp=UDP(sport=67,dport=68)
                bootp=BOOTP(op=2,yiaddr=client_ip,siaddr=server_ip,giaddr='0.0.0.0',chaddr=raw_mac,xid=packet[BOOTP].xid)
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
                sendp(packet_Offer)
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

find_dhcp_traffic()
