import unittest
from agave.core.irdp import IRDP, TYPE_ROUTER_ADVERTISMENT_MESSAGE
from ipaddress import IPv4Address
from agave.core.buffer import Buffer


class TestIRDP(unittest.TestCase):

	IRDP_header = (
		b'\x09\x00\x2e\x42\x01\x02\x07\x08\xc0\xa8\x00\x01\x00\x00\x00\x0a'
	)

	def test_read(self):
		packet = IRDP.read_from_buffer(Buffer.from_bytes(self.IRDP_header))
		self.assertEqual(packet.num_address, 1)
		self.assertEqual(packet.address_entry_size, 2)
		self.assertEqual(packet.life_time, 1800)
		self.assertEqual(packet.type, TYPE_ROUTER_ADVERTISMENT_MESSAGE)
		# TODO, assert address 192.168.0.1
		# TODO, assert preference 10

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = IRDP.read_from_buffer(Buffer.from_bytes(self.IRDP_header))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.IRDP_header)

	def test_advertise_builder(self):
		"""Recreates the test packet."""
		buf = Buffer.from_bytes()
		packet = IRDP.advertise([IPv4Address("192.168.0.1").packed], [10], 1800)
		packet.write_to_buffer(buf)
		self.assertEqual(packet.is_checksum_valid(), True)
		self.assertEqual(bytes(buf), self.IRDP_header)

