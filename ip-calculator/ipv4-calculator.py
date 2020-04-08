#!/usr/bin/python
############################################################

import sys

# Header
print '###[ IP Calculator ]###'
print '###[ Version 0.2 ]###'
print '###[ Date 08/04/2020 ]###'
print '###[ by Bruno Botelho - bruno.botelho.br@gmail.com ]###'
print ''


def _dec_to_binary(ip_address):
    return map(lambda x: bin(x)[2:].zfill(8), ip_address)


def _negation_mask(net_mask):
    wild = list()
    for i in net_mask:
        wild.append(255 - int(i))
    return wild


class IPCalculator(object):
    def __init__(self, ip_address, cdir=24):
        if '/' in ip_address:
            self._address_val, self._cidr = ip_address.split('/')
            self._address = map(int, self._address_val.split('.'))
        else:
            self._address = map(int, ip_address.split('.'))
            self._cidr = cdir
        self.binary_IP = _dec_to_binary(self._address)
        self.binary_Mask = None
        self.negation_Mask = None
        self.network = None
        self.broadcast = None

    def __repr__(self):
        t = self.net_mask()
        t = self.network_ip()
        t = self.broadcast_ip()
        print '###[ Calculating the IP range of %s/%s]###' % (".".join(map(str, self._address)), self._cidr)
        print ''
        print '### Decimal'
        print 'Network ID                %s' % (".".join(map(str, self.network_ip())))
        print 'Netmask                   %s' % (".".join(map(str, self.net_mask())))
        print 'Subnet Broadcast Address  %s' % (".".join(map(str, self.broadcast_ip())))
        print 'Host range                %s' % (self.host_range())
        print 'Max number of hosts       %s' % (self.number_of_host())
        print ''
        print '### Binary'        
        print 'Network ID                %s' % (".".join(map(str, _dec_to_binary(self.network_ip()))))
        print 'Netmask                   %s' % (".".join(map(str, _dec_to_binary(self.net_mask()))))
        print 'Subnet Broadcast Address  %s' % (".".join(map(str, _dec_to_binary(self.broadcast_ip()))))
        print 'Host Range                %s' % (self.host_range_bin())
        print 'Max number of hosts (Dec) %s' % (self.number_of_host())

    def net_mask(self):
        mask = [0, 0, 0, 0]
        for i in range(int(self._cidr)):
            mask[i / 8] += 1 << (7 - i % 8)
        self.binary_Mask = _dec_to_binary(mask)
        self.negation_Mask = _dec_to_binary(_negation_mask(mask))
        return mask

    def broadcast_ip(self):
        broadcast = list()
        for x, y in zip(self.binary_IP, self.negation_Mask):
            broadcast.append(int(x, 2) | int(y, 2))
        self.broadcast = broadcast
        return broadcast

    def network_ip(self):
        network = list()
        for x, y in zip(self.binary_IP, self.binary_Mask):
            network.append(int(x, 2) & int(y, 2))
        self.network = network
        return network

    def host_range(self):
        min_range = self.network
        min_range[-1] += 1
        max_range = self.broadcast
        max_range[-1] -= 1
        return "%s - %s" % (".".join(map(str, min_range)), ".".join(map(str, max_range)))

    def host_range_bin(self):
        min_range = self.network
        min_range[-1] += 1
        max_range = self.broadcast
        max_range[-1] -= 1
        min_range = _dec_to_binary(min_range)
        max_range = _dec_to_binary(max_range)
        return "%s - %s" % (".".join(map(str, min_range)), ".".join(map(str, max_range)))

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
	print 'python ip-calculator.py 192.168.0.1'
	print 'python ip-calculator.py 192.168.0.1/23'
	print ''
	print '* Default mask /24'
	sys.exit(0)
    