#!/usr/bin/env python3
"""rtr_ssh"""

import sys
import os
import subprocess

#
# run this first to prime your known_hosts file
# ssh -N -T -l rpki -p 8283 rtr.rpki.cloudflare.com
#
def rtr_ssh(host, port):
	"""rtr_ssh"""

	ssh = subprocess.Popen(
					[
									'ssh',
									'-N',
									'-T',
									'-o StrictHostKeyChecking=Yes',
									'-o PasswordAuthentication=Yes',
									'-o PreferredAuthentications=password',
									'-l rpki',
									'-p %s' % port,
									host
					],
					shell=False,
					bufsize=-1,
					stdin=subprocess.PIPE,
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE
					)

	#				'-v',
	#				'-o Ciphers=ecdsa-sha2-nistp256',

	# ssh.communicate(b'rpki\n')

	# ssh.stdin.write(b'rpki\n')
	# ssh.stdin.close()

	# reset_query = b'\x01\x02\x00\x00' + b'\x00\x00\x00\x08'
	# ssh.stdin.write(reset_query);
	# ssh.stdin.flush()

	while True:
		result = ssh.stdout.readlines()
		if len(result) == 0:
			error = ssh.stderr.readlines()
			print('ERROR: %s' % (error))
			sys.exit(1)

		print(' LINE: %r' % (result))

def doit(args):
	"""rtr_ssh"""

	rtr_ssh('rtr.rpki.cloudflare.com', 8283)

def main(args=None):
	"""rtr_ssh"""

	if args is None:
		args = sys.argv[1:]
	doit(args)

if __name__ == '__main__':
	main()
