import unittest
from tests.dummy import DummyInterface
from agave.core.arp import *
from agave.core.buffer import Buffer
from agave.core.ethernet import MACAddress
from agave.arp.resolve import Resolver
from ipaddress import IPv4Network, IPv4Address 


class TestARPJobs(unittest.TestCase):

	def test_resolve(self):
		"""Process should return result for given IP only once; replies for data outside
		the scanned subnet should be ignored."""
		job = Resolver(None, DummyInterface("eth0"), IPv4Network("192.168.0.0/24"), 1)
		# build replies
		valid_reply = ARP.is_at(
			MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.1"),
			MACAddress("22:11:33:be:4d:14"), IPv4Address("192.168.0.2")
		)
		invalid_reply = ARP.is_at(
			MACAddress("11:1c:f2:be:4d:14"), IPv4Address("192.168.1.1"),
			MACAddress("22:11:33:be:4d:14"), IPv4Address("192.168.0.2")
		)
		# process reply
		result = job.process(valid_reply, ("eth0", 0x0806, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14'))
		self.assertEqual(result, (MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.1")))
		# process the same reply
		result = job.process(valid_reply, ("eth0", 0x0806, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14'))
		self.assertEqual(result, None)
		# process invalid reply
		result = job.process(invalid_reply, ("eth0", 0x0806, 1, 1, b'\x11\x1c\xf2\xbe\x4d\x14'))
		self.assertEqual(result, None)

