#!/usr/bin/env python3

import sys
import getopt
import json

import ipaddress

from rtr_routes import RoutingTable
from __init__ import __version__

def read_file(routingtable, filename, debug):
	count = 0
	with open('data/routingtable.json', 'r') as fd:
		data = json.load(fd)
		for ip in ['ipv4', 'ipv6']:
			pp = data['routes'][ip]
			for cidr in pp.keys():
				for maxlen in pp[cidr]:
					for x in pp[cidr][maxlen]:
						asn = list(x.keys())[0]
						if debug:
							cidr2 = x[asn]
							# cidr2 should match cidr
							sys.stderr.write("debug: %-30s\t%9d\t%2d\t;\t%s %s\n" % (cidr2, int(asn), int(maxlen), cidr, pp[cidr]))
						routingtable.announce(ipaddress.ip_network(cidr), int(asn), int(maxlen))
						count += 1

	if debug:
		sys.stderr.write("debug: count=%d\n" % (count))
		sys.stderr.flush()

def doit(args=None):
	debug = 0
	filename = 'data/routingtable.json'
	long_flag = False

	usage = ('usage: rtr_show '
		 + '[-H|--help] '
		 + '[-V|--version] '
		 + '[-v|--verbose] '
		 + '[-f|--file] filename '
		 + '[-l|--long] '
		 + 'route'
		 )

	try:
		opts, args = getopt.getopt(args, 'HVvf:l', [
			'help',
			'version',
			'verbose',
			'file=',
			'long'
			])
	except getopt.GetoptError:
		exit(usage)

	for opt, arg in opts:
		if opt in ('-H', '--help'):
			exit(usage)
		if opt in ('-V', '--version'):
			sys.exit('%s: version: %s' % (sys.argv[0], __version__))
		elif opt in ('-v', '--verbose'):
			debug += 1
		elif opt in ('-f', '--file'):
			filename = arg
		elif opt in ('-l', '--long'):
			long_flag = True

	routingtable = RoutingTable()

	read_file(routingtable, filename, debug)
	for route in args:
		try:
			routingtable.show(ipaddress.ip_network(route), long_flag)
		except Exception as e:
			sys.stderr.write('%s: %s\n' % (route, e))
	exit(0)

def main(args=None):
	if args is None:
		args = sys.argv[1:]
	doit(args)

if __name__ == '__main__':
	main()
