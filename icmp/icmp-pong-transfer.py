#!/usr/bin/python
############################################################
#Imports
from scapy.all import *
from termcolor import colored
import base64
import sys
import datetime
import argparse
import binascii

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-w','--write-file', action='store', required=True, dest='output_file',help='[Required] File to write output.')
args = parser.parse_args()

# Configuration
dumpfile = args.output_file
loop = True
ack_list = []

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def ack_icmp(ip_dst,index):
    ip=IP(src=ip_dst)
    icmp=ICMP(type=0, code=0)
    index_c = 'OK' + index
    index_c = index_c.encode("utf-8")
    index_c = base64.b64encode(index_c)
    raw=Raw(index_c)
    pkt = ip/icmp/raw
    #print ('###[ '+ log_timestamp() + '###[ ACK : ' + index + ' Payload > ' + index + ' ]###')
    send(pkt)
    #input("Teste")

def icmp_process(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        payload_base_64 = base64.b64decode(pkt[Raw].load)
        payload_string = payload_base_64.decode('utf-8')
        payload_vetor = payload_string.split('&&')
        if len(payload_vetor) == 2:
            print ('###[ '+ log_timestamp() + ' Writing to ' + colored(dumpfile,'green') + ' Index > ' + colored(payload_vetor[1],'blue') + ' Character > ' + colored(payload_vetor[0].rstrip('\n'),'red') + ' ]###')
            file = open(dumpfile, 'a')
            ack_icmp(pkt[IP].src,payload_string)
            file.write(payload_vetor[0])
            file.close()
            fim = payload_vetor[1].split('/')
            if fim[0] == fim[1]:
                exit()

# Header
print ('###[ ICMP Pong Listener ]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 17/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')


def icmp_mon(): 
    print ('###[ '+ log_timestamp() + ' Starting ICMP Monitoring ]###')
    print ('###[ '+ log_timestamp() + ' File to Write: ' + dumpfile + ' ]###')
    print ('')
    sniff(prn=icmp_process, store=0)
    
icmp_mon()