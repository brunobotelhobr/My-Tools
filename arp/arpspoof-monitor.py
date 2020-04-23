#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# 
############################################################
from scapy.all import *
from termcolor import colored
import datetime
import argparse

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', required=True, action='store',  dest='interface',help='[Required] Set interface to monitor.')
parser.add_argument('-s', required=False, action='store', type=int, dest='sleep_time',help='Sleep time between scans #Defailt 20s')
parser.add_argument('-t', required=False, action='store', type=int, dest='mon_time', help='Loop Time #Default 30s')
parser.add_argument('-once', required=False, action='store_true', help='How many loops? #Default infinite loops')
args = parser.parse_args()

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False
# Setup interface
conf.iface=args.interface
# Sleep Timr
if args.sleep_time:
    sleep_time = args.sleep_time
else:
    sleep_time = 20
# Mon Time
if args.mon_time:
    mon_time = args.mon_time
else:
    mon_time = 30
#Loops Infinitos?
if args.mon_time:
    loop = False
else:
    loop = True

arp_replays = []
arp_list = []
black_list = []

# Header
print ('###[ ARP Spoof Monitor]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 12/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')
print ('INterface       : '+ conf.iface) 
print ('Sleep time      : '+ str(sleep_time)) 
print ('Monitor Timeout : '+ str(mon_time))
print ('Infinite Loops  : '+ str(loop))
print ('')

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def arp_callback(pkt):
    result = ('###[ ' + log_timestamp() + 'ARP Replay ' + colored(pkt[ARP].psrc,'blue') + ' is at ' + colored(pkt[ARP].hwsrc,'blue') + ' ]###')
    mac = pkt[ARP].hwsrc
    ip = pkt[ARP].psrc
    if (result) not in arp_replays:
        print (result)
        #print pkt.summary()
        #print pkt.display()        
        arp_replays.append(result)
        arp_list.append([mac,ip])
        for row in arp_list:
            if ((row[0] == mac) and (row[1] != ip)):
                if row not in black_list:
                    print('!!![ Alert One MAC has more than one ip ' + colored( (mac + ' ' + ip + ' ' + row[1]),'red') + ' ]!!!')
                    black_list.append(row)
                    # Put your Syslog here!

def arp_process(pkt):
    if ARP in pkt and pkt[ARP].op == 2: 
        arp_callback(pkt)

def arp_mon(): 
    sniff(prn=arp_process, store=0, timeout=mon_time)
    print ('###[ ' + log_timestamp() + ' Loop Timeout ' + str(mon_time) + 's  ]###')
    print ('')

if (loop == False):
    arp_mon()
else:
    while True:
        arp_mon()
        arp_replays = []
        arp_list = []
        black_list = []
        time.sleep(sleep_time)
