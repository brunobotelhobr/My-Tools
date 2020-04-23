#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
############################################################

from scapy.all import *
import os
import datetime
import configparser

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Static Configuration
# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-l','--limmit', action='store', required=True, dest='limit',help='[Required] Trigger allert limmit.')
parser.add_argument('-ws','--wite-list', action='store', required=True, dest='ws',help='[Required] Services White List file.')

args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config_file)
localiface = args.interface
localmac = get_if_hwaddr(localiface)

#Configuration
limit = int(args.milit)
cache = []
cache_wipe = 100000

f = open(str(args.ws), 'r')
x = f.readlines()
for i in x:
    print (type(x))
    print (x)
f.close()

white_list = [
    ('10.10.10.110',80,'TCP'),
    ('10.10.10.110',22,'TCP'),
    ('10.10.10.110',53,'UDP')
    ]
for i in white_list:
    print (type(x))
    print (x)

# Header
print ('###[ Port Scanner Detector ]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 04/06/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def cache_limit(pkt_key) : 
    i = 0
    for key in cache:
        if (key[0] == pkt_key[0]):
            i = i+1
    return i


def packet_analyser(pkt):
    if pkt.haslayer(TCP) :
        if pkt[TCP].flags == 2:
            sip = pkt[IP].src
            dip = pkt[IP].dst
            port = pkt[TCP].dport
            pkt_key = [dip,port,'TCP']
            print '###[ Syn Packet Discovered ' + sip + ' to ' + dip + ' on port ' + str(port) + ' TCP ]###'
            print '###[ Cache Size ' + str(len(cache)) + ' / ' +  str(cache_wipe) + ' ]###'
            if pkt_key not in white_list:
                if len(cache) >= cache_wipe:
                    cache.clear
                if pkt_key not in cache:
                    cache.append(pkt_key)
                i = cache_limit(pkt_key)
                if i >= limit:
                    print '!!![ PortScan detected from ' + sip + ' to ' + dip + ' black listed TCP port count ' + str(i) + ' ]!!!'
                    # Put your Syslog / Email function Here
    if pkt.haslayer(UDP) :
        sip = pkt[IP].src
        dip = pkt[IP].dst
        port = pkt[UDP].dport
        pkt_key = [dip,port,'UDP']
        print '###[ Syn Packet Discovered ' + sip + ' to ' + dip + ' on port ' + str(port) + ' UDP ]###'
        print '###[ Cache Size ' + str(len(cache)) + ' / ' +  str(cache_wipe) + ' ]###'
        if pkt_key not in white_list:
            if len(cache) >= cache_wipe:
                cache.clear
            if pkt_key not in cache:
                cache.append(pkt_key)
            i = cache_limit(pkt_key)
            if i >= limit:
                print '!!![ PortScan detected from ' + sip + ' to ' + dip + ' black listed UDP port count ' + str(i) + ' ]!!!'    
                # Put your Syslog / Email function Here


sniff(prn=packet_analyser)