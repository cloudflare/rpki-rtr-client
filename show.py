#!/usr/bin/env python3

import sys
import os
import getopt
import json

import ipaddress

from rtr_routes import RoutingTable

def read_file(routingtable, filename):
	with open('data/routingtable.json', 'r') as fd:
		data = json.load(fd)
		for ip in ['ipv4', 'ipv6']:
			pp = data['routes'][ip]
			for cidr in pp.keys():
				for maxlen in pp[cidr]:
					for x in pp[cidr][maxlen]:
						asn = list(x.keys())[0]
						cidr2 = x[asn]
						# cidr2 should match cidr
						# print("%-30s\t%9d\t%2d\t;\t%s %s" % (cidr2, int(asn), int(maxlen), cidr, pp[cidr]))
				routingtable.announce(ipaddress.ip_network(cidr), int(asn), int(maxlen))

def doit(args=None):
	debug = 0
	filename = 'data/routingtable.json'
	long_flag = False

	usage = ('usage: show '
		 + '[-H|--help] '
		 + '[-v|--verbose] '
		 + '[-f|--file] filename '
		 + '[-l|--long] '
		 + 'route'
		 )

	try:
		opts, args = getopt.getopt(args,
					   'Hvf:l',
					   [
					   	'help',
					   	'version',
						'file=',
						'long',
				
					   ])
	except getopt.GetoptError:
		exit(usage)
	for opt, arg in opts:
		if opt in ('-H', '--help'):
			exit(usage)
		elif opt in ('-v', '--verbose'):
			debug += 1
		elif opt in ('-f', '--file'):
			filename = arg
		elif opt in ('-l', '--long'):
			long_flag = True

	routingtable = RoutingTable()

	read_file(routingtable, filename)
	for route in args:
		routingtable.show(ipaddress.ip_network(route), long_flag)
	exit(0)

def main(args=None):
	if args is None:
		args = sys.argv[1:]
	doit(args)

if __name__ == '__main__':
	main()

