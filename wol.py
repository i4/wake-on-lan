#!/usr/bin/env python3

from pyparsing import *
import argparse
import logging
import psutil
import socket
import sys
import re

def getHosts(dhcp_conf):
	# https://github.com/cbalfour/dhcp_config_parser/blob/master/grammar/host.py
	LBRACE, RBRACE, SEMI = map(Suppress, '{};')
	PERIOD = Literal(".")
	ip = Combine(Word(nums) + PERIOD + Word(nums) + PERIOD + Word(nums) + PERIOD + Word(nums))("ip_address")
	macAddress = Word("abcdefABCDEF0123456789:")
	hostname = Combine(Word(alphanums + "-") + ZeroOrMore(PERIOD + Word(alphanums + "-")))
	comment = (Literal("#") + restOfLine)
	ethernet = (Literal("hardware") + Literal("ethernet") + macAddress("mac") + SEMI)
	address = (Literal("fixed-address") + hostname("address") + SEMI)
	host_stanza = (
		Literal("host") + hostname("host") + LBRACE + (
			ethernet & 
			address
			# TODO: Optional other fields
		) + RBRACE
	)
	host_stanza.ignore(comment)

	hostlist = {}
	for result, start, end in host_stanza.scanString(dhcp_conf.read()):
		hostlist[result['host']] = {
			'address': result['address'],
			'mac': result['mac']
		}
	return hostlist

def getInterface(address):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.connect((address, 0))
	with sock:
		ip, *_ = sock.getsockname()
		for name, confs in psutil.net_if_addrs().items():
			for conf in confs:
				if conf.address == ip and conf.family == socket.AF_INET:
					return name
	return None

def sendMagicPacket(macAddress, iface):
	macRegex = re.compile(r'(?:([0-9a-f]{2})(?:[:-]|$))', re.IGNORECASE)
	macBytes = b''.join([int(b,16).to_bytes(1,'little') for b in macRegex.findall(macAddress)])
	if iface and len(macBytes) == 6:
		try:
			logging.info('Sending magic packet to {} (on {})'.format(macAddress, iface))
			sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			magicPacket = macBytes * 2 + b'\x08\x42' + b'\xff' * 6 + macBytes * 16
			logging.debug('Magic packet for {} is "{}"'.format(macAddress, magicPacket.hex()))
			return sock.sendto(magicPacket, (iface, 7)) == len(magicPacket)
		except Exception as e:
			logging.exception('Sending magic packet to {} (on {}) failed'.format(macAddress, iface))
	return False

def wake(hostname):
	global hosts
	if hostname in hosts:
		logging.info('Waking up {}...'.format(hostname))
		host = hosts[hostname]
		if not 'iface' in host:
			host['iface'] = getInterface(host['address'])
			if host['iface'] is None:
				logging.warning('No interface found for {} ({})!'.format(hostname, host['address']))
				return False
		return sendMagicPacket(host['mac'], host['iface'])
	else:
		logging.warning('Unknown host "{}"'.format(hostname))
		return False

def listen(host, port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((host, port))
		sock.listen(1)
		logging.info('Listening on {}:{}'.format(host, port))
		while True:
			connection, client = sock.accept()
			try:
				hostname = connection.recv(256)
				if hostname:
					logging.info('Request WoL at "{}" from {}'.format(hostname, client))
					connection.sendall(b'success' if wake(hostname.decode('ascii').strip()) else b'failed')
			except KeyboardInterrupt:
				break
			finally:
				connection.close()
	except Exception as e:
		logging.exception('Listening on {}:{} failed'.format(host, port))
	finally:
		sock.close()


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='i4 WakeOnLan Util')
	parser.add_argument('hostnames', nargs='*', help='hostname(s) to send a magic packet')
	parser.add_argument('-c', '--dhcp-conf', metavar='dhcp_conf', type=argparse.FileType('r'), help='Path to DHCP configuration with hostnames', nargs='+', required=True)
	parser.add_argument('-d', '--debug', help="Debug output", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.WARNING)
	parser.add_argument('-v', '--verbose', help="Verbose output", action="store_const", dest="loglevel", const=logging.INFO)

	parser.add_argument('-l', '--listen', action="store_true", help="Listen for hostnames to wake")
	parser.add_argument('-a', '--address', help="Adress to listen on", default="0.0.0.0")
	parser.add_argument('-p', '--port', type=int, help="Port to listen on", default="8423")
	args = parser.parse_args()

	logging.basicConfig(level=args.loglevel)

	hosts = {}
	for conf in args.dhcp_conf:
		hosts.update(getHosts(conf))

	if len(hosts) == 0:
		logging.critical('No hosts configured!')
		sys.exit(1)
	else:
		logging.debug('Found {} host(s) in {} config file(s)'.format(len(hosts), len(args.dhcp_conf)))

	try:
		socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0))
	except Exception as e:
		logging.exception('Creating low level interface socket failed')
		logging.critical('Insufficient permission to send magic packet!')
		sys.exit(1)

	if args.listen:
		if len(args.hostnames) > 0:
			logging.critical('You may either specify hostname(s) or start listening')
			sys.exit(1)
		else:
			listen(args.address, args.port)
	elif len(args.hostnames) == 0:
		logging.critical('You have neither specified hostnames nor listening mode...')
		sys.exit(1)
	else:
		for hostname in args.hostnames:
			wake(hostname)
	sys.exit(0)

