#!/usr/bin/env python3
"""RTR protocol basic Routing Table support"""

import json
import ipaddress

try:
	import pytricia
except:
	pytricia = None

class RoutingTable(object):
	"""RTR protocol basic Routing Table support"""

	def __init__(self):
		"""RTR protocol basic Routing Table support"""

		if not pytricia:
			raise Exception("pytricia not installed")
		self._clear()

	def announce(self, cidr, asn, maxlen=None):
		"""RTR protocol basic Routing Table support"""

		version = cidr.version
		if not maxlen:
			maxlen = cidr.prefixlen
		if not self._ipv[version].has_key(cidr):
			self._ipv[version].insert(cidr, {})
		if maxlen not in self._ipv[version][cidr]:
			# we know we can enter the data raw and be done!
			self._ipv[version][cidr][maxlen] = [{asn:str(cidr)}]
			return

		if asn in self._ipv[version][cidr][maxlen]:
			raise Exception("announce1: %s %s %s" % (cidr,asn,maxlen))
		try:
			self._ipv[version][cidr][maxlen] += [{asn:str(cidr)}]
		except:
			raise Exception("announce2: %s %s %s" % (cidr,asn,maxlen))
			# asn already in there

	def withdraw(self, cidr, asn, maxlen=None):
		"""RTR protocol basic Routing Table support"""

		version = cidr.version
		if not maxlen:
			maxlen = cidr.prefixlen
		if self._ipv[version].has_key(cidr):
			if maxlen in self._ipv[version][cidr]:
				for ii in range(0, len(self._ipv[version][cidr][maxlen])):
					pp = self._ipv[version][cidr][maxlen][ii]
					if asn == list(pp)[0]:
						# found it!
						del self._ipv[version][cidr][maxlen][ii]

						# now clean up data - just because
						if len(self._ipv[version][cidr][maxlen]) == 0:
							del self._ipv[version][cidr][maxlen]
						if len(self._ipv[version][cidr]) == 0:
							self._ipv[version].delete(cidr)
						return
					ii += 1
				##  asn not found

		# clearly we didn't find the route you are trying to withdraw
		raise IndexError("withdraw: %s %s %s" % (cidr,asn,maxlen))

	def dump(self):
		"""RTR protocol basic Routing Table support"""

		self._dump()

	def clear(self):
		"""RTR protocol basic Routing Table support"""

		self._clear()

	def show(self, cidr, show_long=False):
		"""RTR protocol basic Routing Table support"""

		version = cidr.version
		print("%-16s %-16s %6s %s" % ('ROUTE', 'ROA', 'MaxLen', 'ASN'))
		r = None
		if show_long:
			r_temp = {}
			if cidr in self._ipv[version]:
				rr = self._ipv[version][cidr]
				for maxlen in list(rr.keys()):
					if maxlen in r_temp:
						r_temp[maxlen] += rr[maxlen]
					else:
						r_temp[maxlen] = rr[maxlen]
				for child in self._ipv[version].children(cidr):
					rr = self._ipv[version][ipaddress.IPv4Network(child)]
					for maxlen in list(rr.keys()):
						if maxlen in r_temp:
							r_temp[maxlen] += rr[maxlen]
						else:
							r_temp[maxlen] = rr[maxlen]
					# r_temp.update(r3)
			if len(r_temp) > 0:
				r = r_temp
		else:
			if self._ipv[version].has_key(cidr):
				r = self._ipv[version][cidr]

		if r:
			# XXX need to sort/uniq
			for maxlen in r.keys():
				all_routes = r[maxlen]
				for pp in all_routes:
					asn = list(pp)[0]
					route = ipaddress.IPv4Network(pp[asn])
					if maxlen == route.prefixlen:
						s_maxlen = ''
					else:
						s_maxlen = '/' + str(maxlen)
					print("%-16s %-16s %6s %s" % (cidr, route, s_maxlen, 'AS' + str(asn)))

	def _dump(self):
		"""RTR protocol basic Routing Table support"""

		j = {'routes': {'ipv4': self._ipv[4], 'ipv6': self._ipv[6]}}
		with open('data/routingtable.json', 'w') as fd:

			class IPAddressEncoder(json.JSONEncoder):
				def default(self, obj):
					if isinstance(obj, pytricia.PyTricia):
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

	def _clear(self):
		"""RTR protocol basic Routing Table support"""

		# this storage method allows for searching and more
		self._ipv = {4: pytricia.PyTricia(32), 6: pytricia.PyTricia(128)}

