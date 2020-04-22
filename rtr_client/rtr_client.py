#!/usr/bin/env python3
"""RTR client"""

import sys
import os
import getopt
import socket
import select
import time
import json
import ipaddress
from datetime import datetime
from random import randrange

try:
	import pytricia
except:
	pytricia = None

from rtr_protocol import rfc8210router
from __init__ import __version__

#
# rtr protocol - port 8282 - clear text - Cisco, Juniper
# rtr_protocol - port 8283 - ssh - Juniper
# rtr_protocol - port 8284 - tls - ?
#

class Connect(object):
	"""RTR client"""

	rtr_host = 'rtr.rpki.cloudflare.com'
	rtr_port = 8282
	fd = None
	connect_timeout = 5 # this is about the socket connect timeout and not data timeout

	def __init__(self, host=None, port=None):
		if host:
			self.rtr_host = host
		if port:
			self.rtr_port = port
		self.fd = self._connect()

	def close(self):
		self.fd.close()
		self.fd = None

	def recv(self, n):
		try:
			return self.fd.recv(n)
		except Exception as e:
			raise

	def send(self, packet):
		try:
			return self.fd.send(packet)
		except BrokenPipeError as e:
			# remote end closed connection
			sys.stderr.write('send: Broken Pipe %s\n ' % (e))
			sys.stderr.flush()
			raise
		except Exception as e:
			sys.stderr.write('send: Error %s\n ' % (e))
			sys.stderr.flush()
			raise

	def _sleep(self, n):
		# simple back off for failed connect
		time.sleep(n)

	def _connect(self):
		for ii in [1, 2, 4, 8, 16, 32]:
			try:
				fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				fd.settimeout(self.connect_timeout)
				fd.connect((self.rtr_host, self.rtr_port))
				return fd
			except KeyboardInterrupt:
				sys.stderr.write('socket connection: ^C\n')
				sys.stderr.flush()
				sys.exit(1)
			except socket.timeout:
				sys.stderr.write('socket connection: Timeout\n ')
				sys.stderr.flush()
				self._sleep(ii)
				continue
			except socket.error:
				sys.stderr.write('socket connection: Error %s\n ' % (socket.error))
				sys.stderr.flush()
				self._sleep(ii)
				continue
		return None

class Process(object):
	"""RTR client"""

	class Buffer(object):
		"""RTR client"""

		def __init__(self):
			self.last_buffer = None

		def clear(self):
			if self.last_buffer:
				self.last_buffer = None
		def read(self):
			b = self.last_buffer
			if self.last_buffer:
				self.last_buffer = None
			return b

		def write(self, b):
			self.last_buffer = b

	def __init__(self):
		self.buf = self.Buffer()

	def do_hunk(self, rtr_session, v):
		if not v or len(v) == 0:
			# END OF FILE
			return False

		b = self.buf.read()
		if b:
			v = b + v
		data_length = len(v)
		data_left = rtr_session.process(v)
		if data_left > 0:
			self.buf.write(v[data_length - data_left:])
		return True

	def clear(self):
		self.buf.clear()

def now_in_utc():
	"""RTR client"""

	now = datetime.utcnow().replace(tzinfo=None)
	# YYYY-MM-DD-HHMMSS
	return now.strftime('%Y-%m-%d-%H%M%S')

def data_directory(now):
	"""RTR client"""

	# data/YYYY-MM
	try:
		os.mkdir('data')
	except FileExistsError:
		pass
	try:
		os.mkdir('data' + '/' + now[0:7])
	except FileExistsError:
		pass

def dump_routes(rtr_session, serial):
	"""RTR client"""

	# dump present routes into file based on serial number
	routes = rtr_session.routes()
	if len(routes['announce']) > 0 or len(routes['withdraw']) > 0:
		now = now_in_utc()
		data_directory(now)
		j = {'serial': serial, 'routes': routes}
		with open('data/%s/%s.routes.%08d.json' % (now[0:7], now, serial), 'w') as fd:

			class IPAddressEncoder(json.JSONEncoder):
				"""RTR client"""

				def default(self, obj):
					if pytricia and isinstance(obj, pytricia.PyTricia):
						a = {}
						for prefix in obj:
							a[prefix] = obj[prefix]
						return a
					if isinstance(obj, ipaddress.IPv4Network):
						return str(obj)
					if isinstance(obj, ipaddress.IPv6Network):
						return str(obj)
					return json.JSONEncoder.default(self, obj)

			fd.write(json.dumps(j, indent=2, cls=IPAddressEncoder))

		# clean up from this serial number
		rtr_session.clear_routes()
		sys.stderr.write('%s: DUMP ROUTES: serial=%d announce=%d/withdraw=%d\n' %
				 (now_in_utc(), serial, len(routes['announce']), len(routes['withdraw'])))
		sys.stderr.flush()

		# dump the full routing table
		rtr_session.save_routing_table()

def rtr_client(host=None, port=None, serial=None, session_id=None, timeout=None, dump=False, debug=0):
	"""RTR client"""

	rtr_session = rfc8210router(serial=serial, debug=debug)

	if dump:
		data_directory(now_in_utc())
		dump_fd = open('data/__________-raw-data.bin', 'w')

	p = Process()

	have_session_id = False

	connection = None
	while True:
		if not connection:
			connection = Connect(host, port)
			p.clear()
			have_session_id = False
			sys.stderr.write('%s: RECONNECT\n' % (now_in_utc()))
			sys.stderr.flush()

		if not connection:
			sys.stderr.write('\n%s: NO NETWORK CONNECTION\n' % (now_in_utc()))
			sys.stderr.flush()
			sys.exit(1)

		if serial == None or serial == 0:
			packet = rtr_session.reset_query()
			serial = 0
		else:
			packet = rtr_session.serial_query(serial)
		sys.stderr.write('+')
		sys.stderr.flush()
		connection.send(packet)
		rtr_session.process(packet)

		while True:
			# At every oppertunity, see if we have a new session_id number
			try:
				new_session_id = rtr_session.get_session_id()
				if have_session_id:
					if new_session_id != session_id:
						sys.stderr.write('\n%s: REFRESHED SESSION ID %d->%d\n' % (now_in_utc(), session_id, new_session_id))
						sys.stderr.flush()
				else:
					sys.stderr.write('\n%s: NEW SESSION ID %d\n' % (now_in_utc(), new_session_id))
					sys.stderr.flush()
				# update session_id number
				session_id = new_session_id
				have_session_id = True
			except ValueError:
				# no session_id number known yet - should only happen once
				# sys.stderr.write('%s: NO SESSION ID\n' % (now_in_utc()))
				# sys.stderr.flush()
				pass

			# At every oppertunity, see if we have a new serial number
			new_serial = rtr_session.cache_serial_number()
			if new_serial != serial:
				sys.stderr.write('\n%s: NEW SERIAL %d->%d\n' % (now_in_utc(), serial, new_serial))
				sys.stderr.flush()
				# dump present routes into file based on serial number
				dump_routes(rtr_session, new_serial)
				# update serial number
				serial = new_serial

			try:
				# because random timers are your friend!
				delta = 0.2
				this_timeout = int(randrange(timeout * (1-delta), timeout * (1+delta), 1))
				ready = select.select([connection.fd], [], [], this_timeout)
			except KeyboardInterrupt:
				sys.stderr.write('\nselect wait: ^C\n')
				sys.stderr.flush()
				sys.exit(1)
			except Exception as e:
				sys.stderr.write('\nselect wait: %s\n' % (e))
				sys.stderr.flush()
				break

			if not ready[0]:
				# Timeout
				sys.stderr.write('T')
				sys.stderr.flush()

				if rtr_session.time_remaining():
					sys.stderr.write('-')
					sys.stderr.flush()
					continue

				# timed out - go ask for more data!
				packet = rtr_session.serial_query()
				rtr_session.process(packet)
				try:
					sys.stderr.write('s')
					sys.stderr.flush()
					connection.send(packet)
					continue
				except Exception as e:
					sys.stderr.write('send: %s\n' % (e))
					sys.stderr.flush()
					connection.close()
					connection = None
					break

			try:
				sys.stderr.write('.')
				sys.stderr.flush()
				v = connection.recv(64*1024)
			except Exception as e:
				sys.stderr.write('recv: %s\n' % (e))
				sys.stderr.flush()
				v = None
				connection.close()
				connection = None
				break

			if dump:
				# save raw data away
				dump_fd.buffer.write(v)
				dump_fd.flush()

			if not p.do_hunk(rtr_session, v):
				break

def doit(args=None):
	"""RTR client"""

	debug = 0
	dump = False
	host = None
	port = None
	serial = None
	session_id = None
	timeout = 300 # five minutes for some random reason

	usage = ('usage: rtr_client '
		 + '[-H|--help] '
		 + '[-V|--version] '
		 + '[-v|--verbose] '
		 + '[-h|--host] hostname '
		 + '[-p|--port] portnumber '
		 + '[-s|--serial] serialnumber '
		 + '[-t|--timeout] seconds '
		 + '[-d|--dump] '
		 )

	try:
		opts, args = getopt.getopt(args, 'HVvh:p:s:t:d', [
			'help',
			'version',
			'verbose',
			'host=', 'port=',
			'serial=',
			'timeout=',
			'debug'
			])
	except getopt.GetoptError:
		sys.exit(usage)

	for opt, arg in opts:
		if opt in ('-H', '--help'):
			sys.exit(usage)
		if opt in ('-V', '--version'):
			sys.exit('%s: version: %s' % (sys.argv[0], __version__))
		elif opt in ('-v', '--verbose'):
			debug += 1
		elif opt in ('-h', '--host'):
			host = arg
		elif opt in ('-p', '--port'):
			port = int(arg)
		elif opt in ('-s', '--serial'):
			serial = arg
		elif opt in ('-t', '--timeout'):
			timeout = int(arg)
		elif opt in ('-d', '--dump'):
			dump = True

	rtr_client(host=host, port=port, serial=serial, session_id=session_id, timeout=timeout, dump=dump, debug=debug)
	sys.exit(0)

def main(args=None):
	"""RTR client"""

	if args is None:
		args = sys.argv[1:]
	doit(args)

if __name__ == '__main__':
	main()

