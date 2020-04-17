#!/usr/bin/python
############################################################
#Imports
from scapy.all import *
from termcolor import colored
import base64
import datetime
import argparse
import os

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-f','--read-file', action='store', required=True, dest='read_file',help='[Required] File to send by ping.')
parser.add_argument('-t','--target', action='store', required=True, dest='target',help='[Required] Destinaation to send ICMP.')
args = parser.parse_args()


# Configuration
file_to_tranfer = args.read_file
ping_destination = args.target



def convert_bytes(num):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

def file_size(file):
    if os.path.isfile(file):
        file_info = os.stat(file)
        return convert_bytes(file_info.st_size)

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def pong_analyser(pkt,index):
    if pkt == None:
        return False
    else:
        payload_base_64 = base64.b64decode(pkt[Raw].load)
        payload_string = payload_base_64.decode('utf-8')
        if (payload_string  == (index)):
            return True
        else:
            return False

file = open(file_to_tranfer, "r", buffering=-1)
file_data = file.read()
file.close()

# Header
print ('###[ ICMP Ping Transfer ]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 17/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

print ('###[ '+ log_timestamp() + ' File to Transfer: ' + file_to_tranfer + ' ]###')
print ('###[ '+ log_timestamp() + ' File Size: ' + file_size(file_to_tranfer) + ' ]###')
print ('###[ '+ log_timestamp() + ' File Characters: ' + str(len(str(file_data))) + ' ]###')
print ('')

file_characters = len(str(file_data))

i = 0

for c in file_data:
    i = i + 1
    index = str(i) + '/' + str(len(file_data))
    ip=IP(dst=ping_destination)
    icmp=ICMP(type=8, code=0)
    index_c = c + '&&' + index
    raw=Raw(index_c.encode('base64'))
    pkt = ip/icmp/raw
    confirmation = False
    print ('###[ '+ log_timestamp() + ' Transfering: ' + colored(index,'blue') + ' Payload > ' + index_c + ' Character > ' + colored(c,'red') + ' ]###')
    while confirmation == False:
        pck = sr1(pkt)
        confirmation = pong_analyser(pck,index_c)
