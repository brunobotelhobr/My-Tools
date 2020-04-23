#!/usr/bin/python
############################################################

import urllib2
from scapy.all import *
from termcolor import colored
import base64
import datetime
import argparse
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urlparse import urlparse, parse_qs

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-f','--write-file', action='store', required=True, dest='read_file',help='[Required] File to store information')
parser.add_argument('-ip','--server-ip', action='store', required=True, dest='server_ip',help='[Required] Server IP Address')
parser.add_argument('-p','--target-port', action='store', required=True, dest='port',help='[Required] Server Port.')
args = parser.parse_args()

# Configuration
dump_file = str(args.read_file)
http_server_port = int(args.port)
server_ip = str(args.server_ip)

# Header
print ('###[ HTTP Server GET Writer ]###')
print ('###[ Version 0.2 ]###')
print ('###[ Date 22/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

print ('###[ Starting HTTP Server Monitoring ]###')
print ('###[ File to Write: ' + dump_file + ' ]###')
print ('')

def write(j):
    file = open(dump_file, 'a')
    file.write(j)
    file.close()

class StoreHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parameters = parse_qs(urlparse(self.path).query)
        index_c = parameters['p']
        p = str(index_c).decode('base64').split('&&')
        index = p[1]
        index_c = p[0] + '&&' + index
        raw=index_c.encode('base64')
        print ('###[ Received: ' + colored(index,'green') + ' Get > ' + 'http://' + server_ip + '/sys?p=' + colored(str(raw).rstrip('\n'),'red') + ' ]###')
        write(p[0])
        self.send_response(200)
    def log_message(self, format, *args):
        return 

server = HTTPServer(('', 80), StoreHandler)
server.serve_forever()
