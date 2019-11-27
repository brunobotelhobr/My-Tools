from scapy.all import *
import argparse

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-p','--pcap-file', action='store', required=True, 
    dest='pcap',help='File to Interact')
parser.add_argument('-f','--display-filter', action='store', required=False, 
    dest='s_filter',help='Scapy has Layer Filter')
args = parser.parse_args()

pcap = args.pcap
s_filter = args.s_filter

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(pcap)

# Let's iterate through every packet
for packet in packets:
    # We're only interested packets with a DNS Round Robin layer
    if s_filter:
        if packet.haslayer(s_filter):
            packet.display()
            input("Press Enter to continue...")
    else:
        packet.display()
