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

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

# Header
print ('###[ ICMP Ping Payload Monitor ]###')
print ('###[ Version 0.1 ]###')
print ('###[ Date 27/05/2019 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def icml_mon(pkt):
    if pkt.haslayer(ICMP) and pkt.getlayer(ICMP):
        icmp_suspicious = pkt[ICMP].load
        if len(icmp_suspicious) == 56 or len(icmp_suspicious) == 32:
            print ('###[ '+ log_timestamp() + ' Normal payload with size ' + colored(str(len(icmp_suspicious)),'green'))
            pass
        else:
            if len(icmp_suspicious):
                print ('###[ '+ log_timestamp() + ' Suspicious payload with size ' + colored(str(len(icmp_suspicious)),'red') + ' found as: ' + colored(icmp_suspicious,'red'))
                icmp_suspicious = icmp_suspicious.decode('base64')
                print ('###[ '+ log_timestamp() + ' Payload decoded as: ' + colored(icmp_suspicious,'red')) 

sniff(prn=icml_mon)