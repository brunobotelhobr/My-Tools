#!/usr/bin/python
############################################################
#Imports
from scapy.all import *
from termcolor import colored
from ipaddress import IPv4Network
import datetime
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', action='store', required=True, dest='target',help='[Required] Target Network in 192.168.0.0/24 format')
args = parser.parse_args()

# Configuration
network = unicode(args.target)


# Header
print '###[ ICMP Scanner - Pring Sweep]###'
print '###[ Version 0.1 ]###'
print '###[ Date 03/07/2019 ]###'
print '###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###'
print ''

# make list of addresses out of network, set live host counter
addresses = IPv4Network(network)
live_count = 0

# Send ICMP ping request, wait for answer
for host in addresses:
    #print '###[ Test ' + str(host) + ' ]###'
    if host == addresses.broadcast_address:
        print '###[ Skip Bradcast Address ' + host + ' ]###'
        continue
    if host == addresses.network_address:
        print '###[ Skip Network Address ' + str(host) + ' ]###'
        continue

    resp = sr1(
        IP(dst=str(host))/ICMP(),
        timeout=2,
        verbose=0,
    )

    if resp is None:
        print '###[ Host ' + str(host) + ' is down or not responding ]###'
    elif (
        int(resp.getlayer(ICMP).type)==3 and
        int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
    ):
        print '###[ Host ' + str(host) + ' is Blocking Communicatio ]###'
    else:
        print '###[ Host ' + str(host) + ' is responding ]###'
        live_count = live_count + 1

print ''
print '###[ ' + str(live_count) + '/' + str(addresses.num_addresses) + ' hosts are online ]###'
