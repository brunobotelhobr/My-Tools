#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
############################################################

from scapy.all import *
from termcolor import colored
import datetime
import argparse

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

parser = argparse.ArgumentPkaliarser()
parser.add_argument('-i','--interface', action='store', required=True, dest='interface',help='[Required] Set interface to server DHCP services.')
args = parser.parse_args()

# Configuration
localiface = args.interface
localmac = get_if_hwaddr(localiface)
broadcast_mac = 'ff:ff:ff:ff:ff:ff'
sleep_time = 20
mon_time = 20
loop = True
dhcp_replays = []

# Header
print ('###[ DHCP Monitor ]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 20/05/2019 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def dhcp_callback(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:
        result = '###[ ' + log_timestamp() + ' DHCP offer received from: ' + pkt[BOOTP].siaddr + ' ' + pkt[Ether].src + ' ]###'
        #print pkt.summary()
        #print pkt.display()
        if result not in dhcp_replays:
            print (result)
            dhcp_replays.append(result)

def dhcp_mon():
    dhcp_offer_list = []
    ethernet = Ether(src=localmac,dst=broadcast_mac)
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(sport=68,dport=67)
    bootp = BOOTP(chaddr= localmac,xid = RandInt())
    dhcp = DHCP(options=[('message-type', 'discover'),
    ('param_req_list',[1, 121, 3, 6, 15, 119, 252, 44, 46]),
    ('max_dhcp_size', 1500),
    ('client_id', localmac),
    ('lease_time', 43200),
    ('hostname', 'ThiIsSparta!'),
    'end'])
    dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp
    print ('###[ ' + log_timestamp() + ' Send Discovery Packet ]###')
    sendp(dhcp_discover_packet)
    #print dhcp_discover_packet.summary()
    #print dhcp_discover_packet.display()
    sniff(prn=dhcp_callback, store=0, timeout=mon_time)
    if len(dhcp_replays) > 1:
        print ('!!![ ' + log_timestamp() + colored(' More than 1 DHCP Server Replied to your Packet','red') + ']!!!')
        print ('')
        # Put your Syslog / Email function Here
    elif len(dhcp_replays) < 1:
        print ('!!![ ' + log_timestamp() + colored(' Didnt get a reply from anyone, is there a DHCP server on this subnet?','blue') + ']!!!')
        print ('')
        # Put your Syslog / Email function Here
    else:
        print ('###[ ' + log_timestamp() + colored(' Got one DHCP reply, looks good =)','green') + ']###')
        print ('')

if loop == False:
    dhcp_mon()
else:
    while True:
        dhcp_mon()
        dhcp_replays = []
        time.sleep(sleep_time)
