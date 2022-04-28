import unittest
from agave.models.ethernet import ETHER_TYPE_IPV4
from agave.models.llc import LLC, LSAP_SNAP


class TestLLC(unittest.TestCase):

	llc_header = (
		b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
	)

	def test_read_write(self):
		header = LLC.from_bytes(self.llc_header)
		self.assertEqual(header.dsap, LSAP_SNAP)
		self.assertEqual(header.ssap, LSAP_SNAP)
		self.assertEqual(header.control, 0x03)
		self.assertEqual(header.oui, b'\x00\x00\x00')
		self.assertEqual(header.next_header, ETHER_TYPE_IPV4)
		self.assertEqual(header.is_command(), True)
		self.assertEqual(header.is_response(), False)
		self.assertEqual(header.is_unicast(), True)
		self.assertEqual(header.is_multicast(), False)
		self.assertEqual(bytes(header), self.llc_header)

	def test_build(self):
		header = LLC.build_snap(ETHER_TYPE_IPV4)
		self.assertEqual(bytes(header), self.llc_header)

