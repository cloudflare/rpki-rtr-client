#!/usr/bin/env python3
"""RTR RFC 8210 protocol"""

import time
import ipaddress

from rtr_logging import rfc8210logger
from rtr_routes import RoutingTable

class rfc8210router(object):
	"""RTR RFC 8210 protocol"""

	def __init__(self, serial=None, session_id=None, debug=0):
		"""RTR RFC 8210 protocol"""

		self.time_next_refresh = None

		self._debug_level = debug
		if self._debug_level > 0:
			self.logger = rfc8210logger(self._debug_level).getLogger()
		else:
			self.logger = None

		if session_id:
			self._current_session_id = session_id
		else:
			self._current_session_id = None
		self.serial_number = {'latest': 0, 'cache': 0}
		if serial:
			self.serial_number['cache'] = int(serial)	# should be read from data
			self.serial_number['latest'] = int(serial)
		else:
			self.serial_number['cache'] = 0
			self.serial_number['latest'] = 0
		self._refresh_interval = 0
		self._retry_interval = 0
		self._expire_interval = 0
		try:
			self._routingtable = RoutingTable()
		except:
			# this handles the case where RoutingTable() isn't configured correctly
			pass
		self.clear_routes()

	def _debug_(self, msg):
		"""RTR RFC 8210 protocol"""

		if self.logger:
			self.logger.debug(msg)

	def _read_first4bytes(self, d):
		"""RTR RFC 8210 protocol"""

		protocol_version = int(d[0])
		pdu_type = int(d[1])
		session_id = int(d[2]) * 256 + int(d[3])
		# self._debug_('%-16s %d%-16s %d%-16s %d' % ('Protocol Version', protocol_version, 'PDU Type', pdu_type, 'Session ID', session_id))
		return pdu_type, session_id

	def _read_u32bits(self, d):
		"""RTR RFC 8210 protocol"""

		u32 = int(d[0]) * 256 * 256 * 256 + int(d[1]) * 256 * 256 + int(d[2]) * 256 + int(d[3])
		# self._debug_('          uInt32 %d' % (u32))
		return u32

	def _read_4byte_length(self, d):
		"""RTR RFC 8210 protocol"""

		packet_length = int(d[0]) * 256 * 256 * 256 + int(d[1]) * 256 * 256 + int(d[2]) * 256 + int(d[3])
		# self._debug_('          Length %d' % (packet_length))
		return packet_length

	def _read_ipv4(self, d):
		"""RTR RFC 8210 protocol"""

		ipv4 = "%d.%d.%d.%d" % (int(d[0]), int(d[1]), int(d[2]), int(d[3]))
		# self._debug_('              IP %s' % (ipv4))
		return ipv4

	def _read_ipv6(self, d):
		"""RTR RFC 8210 protocol"""

		ipv6 = "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" % (
								int(d[0]) * 256 + int(d[1]),
								int(d[2]) * 256 + int(d[3]),
								int(d[4]) * 256 + int(d[5]),
								int(d[6]) * 256 + int(d[7]),
								int(d[8]) * 256 + int(d[9]),
								int(d[10]) * 256 + int(d[11]),
								int(d[12]) * 256 + int(d[13]),
								int(d[14]) * 256 + int(d[15]))
		# self._debug_('              IP %s' % (ipv6))
		return ipv6

	def _read_asn(self, d):
		"""RTR RFC 8210 protocol"""

		asn = int(d[0]) * 256 * 256 * 256 + int(d[1]) * 256 * 256 + int(d[2]) * 256 + int(d[3])
		# self._debug_('             ASN AS%d' % (asn))
		return asn

	def _write_u32bits(self, u32):
		"""RTR RFC 8210 protocol"""

		s = bytearray(b'\x00\x00\x00\x00')
		s[0] = (u32 >> 24) & 0xff
		s[1] = (u32 >> 16) & 0xff
		s[2] = (u32 >>  8) & 0xff
		s[3] = (u32      ) & 0xff
		return bytes(s)

	def _record_route(self, flag_announce, cidr, asn, maxlen=None):
		"""RTR RFC 8210 protocol"""

		# Save away IP and ASN as needed
		if flag_announce == 'A':
			if maxlen:
				self._routes['announce'] += [{'ip': cidr, 'asn': asn, 'maxlen': maxlen}]
			else:
				self._routes['announce'] += [{'ip': cidr, 'asn': asn}]
			if self._routingtable:
				self._routingtable.announce(cidr, asn, maxlen)
		else:
			if maxlen:
				self._routes['withdraw'] += [{'ip': cidr, 'asn': asn, 'maxlen': maxlen}]
			else:
				self._routes['withdraw'] += [{'ip': cidr, 'asn': asn}]
			if self._routingtable:
				self._routingtable.withdraw(cidr, asn, maxlen)

	def _convert_to_hms(self, secs):
		"""RTR RFC 8210 protocol"""

		return time.strftime('%H:%M:%S', time.gmtime(secs))

	def _process_pdu(self, pdu_type, session_id, d):
		"""RTR RFC 8210 protocol"""

		if pdu_type == 0:
			# Serial Notify
			serial = self._read_u32bits(d[0:4])
			self._debug_('Serial Notify: cache_current_serial=%d latest_current_serial=%d serial=%d' % (
								self.cache_serial_number(),
								self.latest_serial_number(),
								serial))
			self.set_latest_serial_number(serial)
			return True

		if pdu_type == 1:
			# Serial Query - sent by router
			n = self._read_u32bits(d[0:4])
			self._debug_('Serial Query: serial=%d' % (n))
			return True

		if pdu_type == 2:
			# Reset Query - sent by router
			self._debug_('Reset Query:')
			return True

		if pdu_type == 3:
			# Cache Response
			self._debug_('Cache Response: current_session_id=%s session_id=%d' % (self._current_session_id, session_id))
			self._current_session_id = session_id
			return True

		if pdu_type == 4 or pdu_type == 6:
			flags = int(d[0])
			if flags & 0x01 == 0x01:
				flag_announce = 'A' # announcement
			else:
				flag_announce = 'W' # withdrawal
			mask = int(d[1])
			maxlen = int(d[2])
			unused = int(d[3])
			if pdu_type == 6:
				# IPv6
				ip = self._read_ipv6(d[4:4 + 16])
				asn = self._read_asn(d[20:20 + 4])
			else:
				# IPv4
				ip = self._read_ipv4(d[4:4 + 4])
				asn = self._read_asn(d[8:8 + 4])
			cidr = ipaddress.ip_network(ip + '/' + str(mask))
			if mask == maxlen:
				if self._debug_level > 1:
					self._debug_("%1s %-20s %4s AS%d" % (flag_announce, cidr, '', asn))
				self._record_route(flag_announce, cidr, asn)
			else:
				if self._debug_level > 1:
					self._debug_("%1s %-20s %4d AS%d" % (flag_announce, cidr, maxlen, asn))
				self._record_route(flag_announce, cidr, asn, maxlen)
			return True

		if pdu_type == 7:
			# End of Data
			latest_serial_number = self._read_u32bits(d[0:4])
			self._refresh_interval = self._read_u32bits(d[4:8])
			self._retry_interval = self._read_u32bits(d[8:12])
			self._expire_interval = self._read_u32bits(d[12:16])
			self._debug_('End of Data: n_routes=%d/%d serial=%d refresh=%s retry=%s expire=%s' % (
													len(self._routes['announce']),
													len(self._routes['withdraw']),
													latest_serial_number,
													self._convert_to_hms(self._refresh_interval),
													self._convert_to_hms(self._retry_interval),
													self._convert_to_hms(self._expire_interval)
												))
			self.set_latest_serial_number(latest_serial_number)
			self.set_cache_serial_number(latest_serial_number)
			self.time_set_refresh(self._refresh_interval)
			return True

		if pdu_type == 8:
			# Cache Reset
			self._debug_('Cache Reset:')
			self.set_latest_serial_number(0)
			self.set_cache_serial_number(0)
			return True

		if pdu_type == 9:
			# Router Key
			self._debug_('Router Key: ... NOT CODED YET')
			return True

		if pdu_type == 10:
			# Error Report
			self._debug_('Error Report: ... NOT CODED YET')
			return True

		if pdu_type == 255:
			# Reserved
			self._debug_('Reserved:')
			return True

		self._debug_('PDU: %d: Invalid PDU type' % (pdu_type))
		return False

	def process(self, packet_buffer):
		"""RTR RFC 8210 protocol"""

		data_index_max = len(packet_buffer)
		data_index = 0
		while data_index < data_index_max:
			if (data_index_max - data_index) < 8:
				# self._debug_('DATA EXPIRED: not enough for eight bytes')
				break
			d = packet_buffer[data_index:data_index + 4]
			pdu_type, session_id = self._read_first4bytes(d)

			d = packet_buffer[data_index + 4:data_index + 8]
			packet_length = self._read_4byte_length(d)

			if (data_index_max - data_index) < (packet_length):
				# self._debug_('DATA EXPIRED: not enough for eight bytes plus data')
				break

			# We now know we have enough data in the packet

			d = packet_buffer[data_index + 8:data_index+packet_length]
			data_index = data_index + packet_length

			if not self._process_pdu(pdu_type, session_id, d):
				break

		if data_index != data_index_max:
			# self._debug_('DATA EXPIRED: data_index=%d data_index_max=%d' % (data_index, data_index_max))
			pass

		# tell upstream how many bytes left in data
		return data_index_max - data_index

	def serial_query(self, serial=0):
		"""
		   0          8          16         24        31
		   .-------------------------------------------.
		   | Protocol |   PDU    |                     |
		   | Version  |   Type   |     Session ID      |
		   |    1     |    1     |                     |
		   +-------------------------------------------+
		   |                                           |
		   |                 Length=12                 |
		   |                                           |
		   +-------------------------------------------+
		   |                                           |
		   |               Serial Number               |
		   |                                           |
		   `-------------------------------------------'
		"""
		if serial:
			self.set_cache_serial_number(serial)
		serial = self.cache_serial_number()

		s = self._write_u32bits(serial)
		serial_query = b'\x01\x01\x00\x00' + b'\x00\x00\x00\x0c' + s
		return serial_query

	def reset_query(self):
		"""
		   0          8          16         24        31
		   .-------------------------------------------.
		   | Protocol |   PDU    |                     |
		   | Version  |   Type   |         zero        |
		   |    1     |    2     |                     |
		   +-------------------------------------------+
		   |                                           |
		   |                 Length=8                  |
		   |                                           |
		   `-------------------------------------------'
		"""
		self.set_latest_serial_number(0)
		self.set_cache_serial_number(0)
		reset_query = b'\x01\x02\x00\x00' + b'\x00\x00\x00\x08'
		return reset_query

	def get_session_id(self):
		"""RTR RFC 8210 protocol"""

		return self._current_session_id

	def latest_serial_number(self):
		"""RTR RFC 8210 protocol"""

		return self.serial_number['latest']

	def set_latest_serial_number(self, serial):
		"""RTR RFC 8210 protocol"""

		self.serial_number['latest'] = serial
		return self.serial_number['latest']

	def cache_serial_number(self):
		"""RTR RFC 8210 protocol"""

		return self.serial_number['cache']

	def set_cache_serial_number(self, serial):
		"""RTR RFC 8210 protocol"""

		self.serial_number['cache'] = serial
		return self.serial_number['cache']

	def time_now(self):
		"""RTR RFC 8210 protocol"""

		return int(time.time())

	def time_set_refresh(self, t):
		"""RTR RFC 8210 protocol"""

		if t > 60:
			# CHEAT
			t = 60
		self.time_next_refresh = self.time_now() + t

	def time_remaining(self):
		"""RTR RFC 8210 protocol"""

		now = self.time_now()
		if self.time_next_refresh and now < self.time_next_refresh:
			return True
		self.time_set_refresh(15)
		return False

	def dump(self):
		"""RTR RFC 8210 protocol"""

		if self._routingtable:
			self._routingtable.dump()

	def routes(self):
		"""RTR RFC 8210 protocol"""

		return self._routes

	def clear_routes(self):
		"""RTR RFC 8210 protocol"""

		self._routes = {'announce': [], 'withdraw': []}
		if self._routingtable:
			self._routingtable.clear()

