#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
############################################################

import time
import logging
from scapy.all import *
import argparse
import datetime

# To stop scapy from checking return packet originating from any packet that we have sent out
conf.checkIPaddr=False

# Disable default scapy output
conf.verb = 0

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', action='store', required=True, dest='target',help='[Required] Target Address, ex 10.10.10.10')
parser.add_argument('-all', required=False, action='store_true', help='[Optional] Scan all TCP ports, by default just 1 to 1024')
parser.add_argument('-min', required=False, action='store_true', help='[Optional] Scan min  TCP ports ( 1 - 254), by default just 1 to 1024')
args = parser.parse_args()

#Configuration
target_ip =  str(args.target)
closed_ports = 0
open_ports = []
if args.all :
    ports = range(1, 65535)
else:
    if args.min:
        ports = range(1, 254)
    else:
        ports = range(1, 1024)
start_time = time.time()

# Header
print ('###[ UDP Port Scanner ]###')
print ('###[ Version 0.4 ]###')
print ('###[ Date 22/04/2020 ]###')
print ('###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###')
print ('')

def log_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def host_is_up(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True
 
if host_is_up(target_ip):
    print ('###[ '+ log_timestamp() + ' Host %s is up, start scanning ]###' % target_ip)
    for port in ports:
        src_port = RandShort()
        ip = IP(dst=target_ip)
        udp = UDP(sport=src_port, dport=port)
        pkt = ip / udp
        resp = sr1(pkt, timeout=2)
        print ('###[ '+ log_timestamp() + ' Trying port %s ]###' % port)
        if str(type(resp)) == "<type 'NoneType'>":
            open_ports.append(port)
        else:
            closed_ports += 1
    duration = time.time()-start_time
    print ('')
    print ('###[ '+ log_timestamp() + '%s Scan Completed in %fs ]###' % (target_ip, duration))
    print ('')
    if len(open_ports) != 0:
        for k in open_ports:
            print ('###[ '+ log_timestamp() + ' Port %d open ]###' % k)
        print ('')
        print ('###[ '+ log_timestamp() + ' %d ports closed ports in %d total port scanned ]###' % (closed_ports, len(ports)))
else:
    print ('')
    print ('###[ '+ log_timestamp() + ' Host %s is Down ]###' % target_ip)
    print ('')