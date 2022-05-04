import unittest
from agave.models.icmp.irdp import IRDP, TYPE_ROUTER_ADVERTISMENT_MESSAGE
from ipaddress import IPv4Address


class TestIRDP(unittest.TestCase):

	IRDP_header = (
		b'\x09\x00\x2e\x42\x01\x02\x07\x08\xc0\xa8\x00\x01\x00\x00\x00\x0a'
	)

	def test_parse(self):
		packet = IRDP.from_bytes(self.IRDP_header)
		self.assertEqual(packet.num_address, 1)
		self.assertEqual(packet.address_entry_size, 2)
		self.assertEqual(packet.life_time, 1800)
		self.assertEqual(packet.type, TYPE_ROUTER_ADVERTISMENT_MESSAGE)
		addresses = list(packet.get_addresses())
		self.assertEqual(len(addresses), 1) 							# number of addresses
		self.assertEqual(addresses[0][0], IPv4Address("192.168.0.1")) 	# router
		self.assertEqual(addresses[0][1], 10) 							# preference
		# reassemble
		self.assertEqual(bytes(packet), self.IRDP_header)

	def test_advertise_builder(self):
		"""Recreates the test packet."""
		packet = IRDP.advertise([(IPv4Address("192.168.0.1"), 10)], 1800)
		self.assertEqual(packet.is_checksum_valid(), True)
		self.assertEqual(bytes(packet), self.IRDP_header)

