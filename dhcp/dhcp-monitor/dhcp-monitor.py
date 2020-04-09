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
localiface = 'en0'
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
    return colored(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 'grey')


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
    dhcp = DHCP(options=[('message-type', 'discover'), 'end'])
    dhcp_discover_packet = ethernet / ip / udp / bootp / dhcp
    sendp(dhcp_discover_packet)
    print ('###[ ' + log_timestamp() + ' Send Discovery Packet ]###')
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
    for i in dhcp_replays:
        print (i.display())

if loop == False:
    dhcp_mon()
else:
    while True:
        dhcp_mon()
        dhcp_replays = []
        time.sleep(sleep_time)
