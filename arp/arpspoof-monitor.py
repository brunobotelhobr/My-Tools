#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
############################################################
from termcolor import colored
import datetime
import argparse
import logging
import time
from scapy.all import conf, sniff
from scapy.layers.l2 import ARP

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

NAME = "Arp Spoofing Detector"
VERSION = "1.0"
DATE = "02/06/2024"
SLEEP_TIME = 20
MON_TIME = 30
LOOP = True
ARP_REPLY_LIST = []
ARP_LIST = []
BLACK_LIST = []


def parse_arguments():
    """Parse and return arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        required=True,
        action="store",
        dest="interface",
        help="Interface to use for ARP attacks detection.",
    )
    parser.add_argument(
        "-s",
        required=False,
        action="store",
        type=int,
        dest="sleep_time",
        help="Sleep time between scans #Defailt 20s",
    )
    parser.add_argument(
        "-t",
        required=False,
        action="store",
        type=int,
        dest="mon_time",
        help="Loop Time #Default 30s",
    )
    parser.add_argument(
        "-once",
        required=False,
        action="store_true",
        help="How many loops? #Default infinite loops",
    )
    return parser.parse_args()


def setup(args):
    """Setup the environment based on provided arguments."""
    conf.verb = 0  # Disable default scapy output
    conf.checkIPaddr = False  # Disable scapy IP address check
    conf.iface = args.interface  # Set the interface to use
    # Sleep Timr
    if args.sleep_time:
        SLEEP_TIME = args.sleep_time
    # Mon Time
    if args.mon_time:
        MON_TIME = args.mon_time
    # Loops Infinitons
    if args.mon_time:
        LOOP = False


def print_banner():
    """Print the banner."""
    print(f"###[ {NAME} ]###")
    print(f"###[ Version {VERSION} ]###")
    print(f"###[ Date {DATE} ]###")
    print("###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###")
    print("")
    print("Interface       : " + conf.iface)
    print("Sleep time      : " + str(SLEEP_TIME))
    print("Monitor Timeout : " + str(MON_TIME))
    print("Infinite Loops  : " + str(LOOP))
    print("")


def log_timestamp():
    """Return the current timestamp."""
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def arp_callback(pkt):
    """Callback function for ARP packets."""
    result = (
        "###[ "
        + log_timestamp()
        + " ARP Replay "
        + colored(pkt[ARP].psrc, "blue")
        + " is at "
        + colored(pkt[ARP].hwsrc, "blue")
        + " ]###"
    )
    mac = pkt[ARP].hwsrc
    ip = pkt[ARP].psrc
    if (result) not in arp_replays:
        print(result)
        arp_replays.append(result)
        arp_list.append([mac, ip])
        for row in arp_list:
            if (row[0] == mac) and (row[1] != ip):
                if row not in black_list:
                    print(
                        "!!![ Alert One MAC has more than one ip "
                        + colored((mac + " " + ip + " " + row[1]), "red")
                        + " ]!!!"
                    )
                    black_list.append(row)
                    # Put your Syslog here!


def arp_process(pkt):
    """Process ARP packets."""
    if ARP in pkt and pkt[ARP].op == 2:
        arp_callback(pkt)


def arp_mon():
    """Monitor ARP packets."""
    sniff(prn=arp_process, store=0, timeout=MON_TIME)
    print("###[ " + log_timestamp() + " Loop Timeout " + str(MON_TIME) + "s  ]###")
    print("")


arp_replays = []
arp_list = []
black_list = []

if LOOP is False:
    arp_mon()
else:
    while True:
        arp_mon()
        time.sleep(SLEEP_TIME)
