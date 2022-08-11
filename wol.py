#!/usr/bin/env python3

from pyparsing import *
from typing import Dict, Optional
import socketserver
import argparse
import logging
import psutil
import socket
import sys
import os
import re

def getHosts(dhcp_conf) -> Dict[str, Dict[str, str]]:
	# https://github.com/cbalfour/dhcp_config_parser/blob/master/grammar/host.py
	LBRACE, RBRACE, SEMI = map(Suppress, '{};')
	PERIOD = Literal('.')
	ip = Combine(Word(nums) + PERIOD + Word(nums) + PERIOD + Word(nums) + PERIOD + Word(nums))('ip_address')
	macAddress = Word('abcdefABCDEF0123456789:')
	hostname = Combine(Word(alphanums + '-') + ZeroOrMore(PERIOD + Word(alphanums + '-')))
	comment = (Literal('#') + restOfLine)
	ethernet = (Literal('hardware') + Literal('ethernet') + macAddress('mac') + SEMI)
	address = (Literal('fixed-address') + hostname('address') + SEMI)
	host_stanza = (
		Literal('host') + hostname('host') + LBRACE + (
			ethernet &
			address
			# TODO: Optional other fields
		) + RBRACE
	)
	host_stanza.ignore(comment)

	hostlist = {}  # type: Dict[str, Dict[str, str]]
	for result, start, end in host_stanza.scanString(dhcp_conf.read()):
		hostlist[result['host']] = {
			'address': result['address'],
			'mac': result['mac']
		}

	logging.debug('Parsed configuration file "{}" with {} entries.'.format(dhcp_conf.name, len(hostlist)))
	return hostlist

def getInterface(address: str) -> Optional[str]:
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.connect((address, 0))
	with sock:
		ip, *_ = sock.getsockname()
		for name, confs in psutil.net_if_addrs().items():
			for conf in confs:
				if conf.address == ip and conf.family == socket.AF_INET:
					return name
	return None

magicPort = 9
magicRAW = False
def sendMagicPacket(macAddress: str, iface: str) -> bool:
	macRegex = re.compile(r'(?:([0-9a-f]{2})(?:[:-]|$))', re.IGNORECASE)
	macBytes = b''.join([int(b,16).to_bytes(1,'little') for b in macRegex.findall(macAddress)])
	if iface and len(macBytes) == 6:
		try:
			logging.info('Sending magic packet to {} (on {})'.format(macAddress, iface))
			if magicRAW:
				sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0))
				address = (iface, magicPort)
			else:
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				sock.setsockopt(socket.SOL_SOCKET, 25, str(iface + '\0').encode('utf-8'))
				address = ('<broadcast>', magicPort)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			magicPacket = macBytes * 2 + b'\x08\x42' + b'\xff' * 6 + macBytes * 16
			logging.debug('Magic packet for {} is "{}"'.format(macAddress, magicPacket.hex()))
			return sock.sendto(magicPacket, address) == len(magicPacket)
		except Exception as e:
			logging.exception('Sending magic packet to {} (on {}) failed'.format(macAddress, iface))
	return False

def wake(hostname: str) -> bool:
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

class WakeRequestHandler(socketserver.StreamRequestHandler):
	def handle(self):
		self.connection.settimeout(6)
		client = self.client_address[0]
		logging.debug('Connected {}'.format(client))
		try:
			while self.rfile:
				hostname = self.rfile.readline().decode('ascii').strip()
				if hostname:
					logging.info('Request WoL at "{}" from {}'.format(hostname, client))
					self.wfile.write(b"success\n" if wake(hostname) else b"failed\n")
				else:
					break
		except socket.timeout:
			logging.debug('Timeout of {}'.format(client))

def listen(host: str, port: int) -> None:
	with socketserver.ForkingTCPServer((host, port), WakeRequestHandler, False) as server:
		server.socket_type = socket.SOCK_STREAM
		server.allow_reuse_address = True
		server.server_bind()
		server.server_activate()
		logging.info('Listening on {}:{}'.format(host, port))
		try:
			server.serve_forever()
		except KeyboardInterrupt:
			logging.info('Exit due to keyboard interrupt')
			server.server_close()
			sys.exit(0)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='i4 WakeOnLan Util')
	parser.add_argument('hostnames', nargs='*', help='hostname(s) to send a magic packet')
	parser.add_argument('-C', '--dhcp-dir', metavar='dhcp_dir', help='Path to DHCP configuration directory', default='/etc/wake-on-lan')
	parser.add_argument('-c', '--dhcp-conf', metavar='dhcp_conf', type=argparse.FileType('r'), help='Path to additional DHCP configuration files with hostnames', nargs='*')
	parser.add_argument('-d', '--debug', help="Debug output", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.WARNING)
	parser.add_argument('-v', '--verbose', help="Verbose output", action="store_const", dest="loglevel", const=logging.INFO)
	parser.add_argument('-m', '--magic-port', type=int, help="Port for magic packet", dest="magic_port", default=magicPort )
	parser.add_argument('-r', '--raw', help="Use RAW socket ", action="store_true", dest="magic_raw" )

	parser.add_argument('-l', '--listen', action="store_true", help="Listen for hostnames to wake")
	parser.add_argument('-a', '--address', help="Adress to listen on", default="0.0.0.0")
	parser.add_argument('-p', '--port', type=int, help="Port to listen on", default="8423")
	args = parser.parse_args()

	logging.basicConfig(level=args.loglevel)
	magicPort = args.magic_port
	magicRAW = args.magic_raw

	hosts = {}
	files = 0

	if os.path.isdir(args.dhcp_dir):
		for conffile in os.listdir(args.dhcp_dir):
			if conffile.endswith('.conf'):
				with open(os.path.join(args.dhcp_dir, conffile), 'r') as conf:
					hosts.update(getHosts(conf))
					files = files + 1

	if args.dhcp_conf:
		for conf in args.dhcp_conf:
			hosts.update(getHosts(conf))
			files = files + 1

	if len(hosts) == 0:
		logging.critical('No hosts configured!')
		sys.exit(1)
	else:
		logging.debug('Found {} host(s) in {} config file(s)'.format(len(hosts), files))

	try:
		if magicRAW:
			socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0))
		else:
			socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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
