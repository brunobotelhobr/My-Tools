#!/usr/bin/python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', 
    required ='False', 
    type = string,
    action='store_true', 
    help="Set interface to use, default eth0")
args = parser.parse_args()
print (args)
