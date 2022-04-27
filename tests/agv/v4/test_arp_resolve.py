import unittest
from tests.dummy import DummyInterface
from agave.models.arp import ARP
from agave.models.ethernet import MACAddress, ETHER_TYPE_ARP
from agv.v4.arp.resolve import Resolver
from ipaddress import IPv4Network, IPv4Address 


class TestARPResolver(unittest.TestCase):

	job = Resolver(None, DummyInterface(), IPv4Network("192.168.0.0/24"), 1)

	def test_resolve(self):
		"""Process should return sender IP and MAC only once."""
		result = self.job.process(
			ARP.is_at(
				MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.1"),
				MACAddress("22:11:33:be:4d:14"), IPv4Address("192.168.0.2")
			), 
			("eth0", ETHER_TYPE_ARP, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14')
		)
		self.assertEqual(result, (MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.1")))

	def test_duplicate(self):
		"""Process should return result for given IP only once."""
		message = (
			ARP.is_at(
				MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.6"),
				MACAddress("22:11:33:be:4d:14"), IPv4Address("192.168.0.2")
			), 
			("eth0", ETHER_TYPE_ARP, 1, 1, b'\x00\x1c\xf2\xbe\x4d\x14')
		)
		self.assertEqual(
			self.job.process(*message),
			(MACAddress("00:1c:f2:be:4d:14"), IPv4Address("192.168.0.6"))
		)
		self.assertEqual(
			self.job.process(*message),
			None
		)

	def test_ignore_reply(self):
		"""Replies for data outside the scanned subnet should be ignored."""
		result = self.job.process(
			ARP.is_at(
				MACAddress("11:1c:f2:be:4d:14"), IPv4Address("192.168.1.1"),
				MACAddress("22:11:33:be:4d:14"), IPv4Address("192.168.0.2")
			),
			("eth0", ETHER_TYPE_ARP, 1, 1, b'\x11\x1c\xf2\xbe\x4d\x14')
		)
		self.assertEqual(result, None)

