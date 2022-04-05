import unittest
from tests.dummy import DummyInterface
from agave.core.arp import *
from agave.core.buffer import Buffer
from agave.core.ethernet import MACAddress
from agave.arp.resolve import Resolver
from ipaddress import IPv4Network, IPv4Address 


class TestARP(unittest.TestCase):

	ETH_1 = (
		b'\x3c\xaa\x67\x22\x02\x22\x00\x1c\xf2\xbe\x4d\x14\x08\x06'
	)
	ARP_1 = (
		b'\x00\x01\x08\x00\x06\x04\x00\x02\x00\x1c\xf2\xbe\x4d\x14'
		b'\xc0\xa8\x00\x01\x3c\xaa\x67\x22\x02\x22\xc0\xa8\x00\x69'
	)
	REPLY = ETH_1 + ARP_1

	def test_resolve(self):
		"""Process should return result for given IP only once."""
		job = Resolver(None, DummyInterface("eth0"), IPv4Network("192.168.0.0/24"), 1)
		# process reply
		result = job.process(self.REPLY, ("eth0", 0x0806, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14'))
		self.assertEqual(result, (MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.1")))
		# process the same reply
		result = job.process(self.REPLY, ("eth0", 0x0806, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14'))
		self.assertEqual(result, None)

	def test_resolve_from_different_network(self):
		"""Replies from different subnet should be ignored."""
		job = Resolver(None, DummyInterface("eth0"), IPv4Network("192.168.1.0/24"), 1)
		result = job.process(self.REPLY, ("eth0", 0x0806, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14'))
		self.assertEqual(result, None)
