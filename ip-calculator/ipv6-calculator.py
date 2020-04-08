#!/usr/bin/python
############################################################

import sys

# Header
print '###[ IPv6 Calculator ]###'
print '###[ Version 0.2 ]###'
print '###[ Date 06/06/2019 ]###'
print '###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###'
print ''

def zerofill(list,size):
    resp = []
    for n in list:
        resp.append(str(n).rjust(size,'0'))
    return resp

def decimal_to_bin(list):
    resp = []
    for n in list:
        resp.append(str(bin(n))[2:])
    return resp

def decimal_to_hex(list):
    resp = []
    for n in list:
        resp.append(str(hex(n))[2:])
    return resp

def bin_to_decimal(n):
    return int(n, 2)

def bin_to_hex(n):
    n = bin_to_decimal(n)
    return decimal_to_bin(n)

def hex_to_bin(list):
    resp = []
    for n in list:
        resp.append(str(bin(int(n, 16)))[2:])
    return resp
    
def hex_decimal(n):
    return int(n, 16)
    
def negation_mask(net_mask):
    wild = list()
    for i in net_mask:
        wild.append(65535 - int(i))
    return wild

def full_fill_ip(addr):
    if '::' not in addr:
        return addr
    if addr.endswith('::'):
        addr = addr[:-2]
        addr_list = addr.split(':')
        size = len(addr_list)
        while size < 8:
            addr_list.append('0000')
            size = size +1
        return addr_list[0] + ':' + addr_list[1] + ':' + addr_list[2] + ':' + addr_list[3] + ':'\
            + addr_list[4] + ':' + addr_list[5] + ':' + addr_list[6] + ':' + addr_list[7]
            


class IPCalculator(object):
    def __init__(self, ip_address, cdir=64):
        if '/' in ip_address:
            self._address_val, self._cidr = ip_address.split('/')
            self._address_val = full_fill_ip(self._address_val)
            self._address = self._address_val.split(':')
        else:
            ip_address = full_fill_ip(ip_address)
            self._address = ip_address.split(':')
            self._cidr = cdir
        self.binary_IP = zerofill(hex_to_bin(self._address),16)
        self.binary_Mask = None
        self.negation_Mask = None
        self.network = None
        self.broadcast = None

    def __repr__(self):
        x = self.net_mask()
        print '###[ Calculating the IP range of %s/%s]###' % (":".join(map(str, self._address)), self._cidr)
        print ''
        print '### Hexa'
        print 'Network ID                %s' % (":".join(map(str, self.network_ip())))
        print 'Netmask                   %s' % (":".join(map(str, self.net_mask())))
        print 'Subnet Broadcast Address  %s' % (":".join(map(str, self.broadcast_ip())))
        print 'Host Range                %s' % (self.host_range())
        print 'Max Number of Hosts       %s' % (self.number_of_host())
        print ''
        print '### Binary'
        print 'Network ID                %s' % (":".join(map(str, zerofill(hex_to_bin(self.network_ip()),16))))
        print 'Netmask                   %s' % (":".join(map(str, zerofill(hex_to_bin(self.net_mask()),16))))
        print 'Subnet Broadcast Address  %s'% (":".join(map(str, zerofill(hex_to_bin(self.broadcast_ip()),16))))
        print 'Host Range                %s' % (self.host_range_bin())
        print 'Max Number of Hosts (Dec) %s' % (self.number_of_host())


    def net_mask(self):
        mask = [0, 0, 0, 0, 0, 0, 0, 0]
        for i in range(int(self._cidr)):
            mask[i / 16] += 1 << (15 - i % 16)
        self.binary_Mask = zerofill(decimal_to_bin(mask),16)
        self.negation_Mask = zerofill(decimal_to_bin(negation_mask(mask)),16)
        return zerofill(decimal_to_hex(mask),4)

    def broadcast_ip(self):
        broadcast = list()
        for x, y in zip(self.binary_IP, self.negation_Mask):
            broadcast.append(int(x, 2) | int(y, 2))
        self.broadcast = broadcast
        return zerofill(decimal_to_hex(broadcast),4)

    def network_ip(self):
        network = list()
        for x, y in zip(self.binary_IP, self.binary_Mask):
            network.append(int(x, 2) & int(y, 2))
        self.network = network
        return zerofill(decimal_to_hex(network),4)

    def host_range(self):
        min_range = self.network
        min_range[-1] += 1
        max_range = self.broadcast
        max_range[-1] -= 1
        a = zerofill(decimal_to_hex(min_range),4)
        b = zerofill(decimal_to_hex(max_range),4)
        return "%s - %s" % (":".join(map(str, a)), ":".join(map(str, b)))

    def host_range_bin(self):
        min_range = self.network
        min_range[-1] += 1
        max_range = self.broadcast
        max_range[-1] -= 1
        a = zerofill(decimal_to_bin(min_range),16)
        b = zerofill(decimal_to_bin(max_range),16)
        return "%s - %s" % (":".join(map(str, a)), ":".join(map(str, b)))

    def number_of_host(self):
        return (2 ** sum(map(lambda x: sum(c == '1' for c in x), self.negation_Mask))) - 2


def ip_calculate(ip):
    ip = IPCalculator(ip)
    ip.__repr__()

if len(sys.argv) != 1:
    ip = sys.argv[1] 
    ip_calculate(ip)
else: 
    print 'Usage:'
    print 'python ip-calculator.py 2002:76f5:AB12::/64'
    print 'python ip-calculator.py 2002:cfcf:ab12::'
    print 'python ip-calculator.py 2002:76f5:AB12:0000:0000:0000:0000:0001/64'
    print 'python ip-calculator.py 2002:cfcf:ab12:0000:0000:0000:0000:0002'
    print ''
    print '* Default mask /64'
    sys.exit(0)
