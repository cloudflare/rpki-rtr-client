#!/usr/bin/env python3

import sys

from rtr_protocol import rfc8210router

def doit(filename):
	rtr_session = rfc8210router(serial=0, debug=2)

	with open(filename, 'rb') as fd:
		# read whole file and then process it
		v = fd.read()
		rtr_session.process(v)

def main(args=None):
	if args is None:
		args = sys.argv[1:]

	filename = 'data/__________-raw-data.bin'
	doit(filename)

if __name__ == '__main__':
	main()

