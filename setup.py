#!/usr/bin/env python
"""RTR RFC 8210 protocol"""

import re
from setuptools import setup, find_packages

_version_re = re.compile(r"__version__\s=\s'(.*)'")

def main():
	"""RTR RFC 8210 protocol"""

	with open('README.rst') as read_me:
		long_description = read_me.read()

	with open('rtr_client/__init__.py', 'r') as f:
		version = _version_re.search(f.read()).group(1)

	setup(
		name='rpki-rtr-client',
		version=version,
		description='A simple client-side implementation of the RTR RFC8210 protocol in Python',
		long_description=long_description,
		author='Martin J. Levy',
		author_email='martin@cloudflare.com',
		url='https://github.com/cloudflare/rpki-rtr-client',
		license='BSD 3',
		packages=['rtr_client']+find_packages(),
		include_package_data=True,
		install_requires=['pytricia'],
		keywords='RFC9210, RPKI, RTR, Cloudflare',
		entry_points={
			'console_scripts': [
				'rtr_client=rtr_client.__main__:main',
				'rtr_show=rtr_client.rtr_show.__main__:main',
			]
		},
		classifiers=[
			'Development Status :: 5 - Production/Stable',
			'Intended Audience :: Developers',
			'Topic :: Software Development :: Libraries :: Python Modules',
			'License :: OSI Approved :: MIT License',
			'Programming Language :: Python :: 3',
		]
	)

if __name__ == '__main__':
	main()
