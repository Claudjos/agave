import unittest
from agave.models.ethernet import Ethernet, ETHER_TYPE_IPV4, MACAddress
from agave.models.buffer import Buffer


class TestEthernet(unittest.TestCase):

	ethernet_header = (
		b'\x00\x0c\xf6\xaa\x33\x04\x3c\xa0\x55\x2e\x11\x22\x08\x00'
	)

	def test_read(self):
		packet = Ethernet.read_from_buffer(Buffer.from_bytes(self.ethernet_header))
		self.assertEqual(packet.destination, b'\x00\x0c\xf6\xaa\x33\x04')
		self.assertEqual(packet.source, b'\x3c\xa0\x55\x2e\x11\x22')
		self.assertEqual(packet.next_header, ETHER_TYPE_IPV4)

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = Ethernet.read_from_buffer(Buffer.from_bytes(self.ethernet_header))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.ethernet_header)

	def test_conversion(self):
		self.assertEqual(
			b'\xff\xee\xdd\x00\x02\x04',
			MACAddress.str_to_mac("ff:ee:dd:00:02:04")
		)
		self.assertEqual(
			"ff:ee:dd:00:02:04",
			MACAddress.mac_to_str(MACAddress.str_to_mac("ff:ee:dd:00:02:04"))
		)

	def test_addresses(self):
		mac = MACAddress("01:00:5e:00:00:01")
		self.assertEqual(mac.is_ipv4_multicast(), True)
		self.assertEqual(mac.is_ipv6_multicast(), False)
		self.assertEqual(mac.is_multicast(), True)
		self.assertEqual(mac.is_unicast(), False)
		self.assertEqual(mac.is_universal(), True)
		self.assertEqual(mac.is_local(), False)
		self.assertEqual(mac.is_broadcast(), False)
		mac = MACAddress("33:33:00:00:00:01")
		self.assertEqual(mac.is_ipv4_multicast(), False)
		self.assertEqual(mac.is_ipv6_multicast(), True)
		self.assertEqual(mac.is_multicast(), True)
		self.assertEqual(mac.is_unicast(), False)
		self.assertEqual(mac.is_universal(), False)
		self.assertEqual(mac.is_local(), True)
		self.assertEqual(mac.is_broadcast(), False)
		mac = MACAddress("00:0c:f6:be:4d:04")
		self.assertEqual(mac.oui, b'\x00\x0c\xf6')
		self.assertEqual(mac.is_ipv4_multicast(), False)
		self.assertEqual(mac.is_ipv6_multicast(), False)
		self.assertEqual(mac.is_multicast(), False)
		self.assertEqual(mac.is_unicast(), True)
		self.assertEqual(mac.is_universal(), True)
		self.assertEqual(mac.is_local(), False)
		self.assertEqual(mac.is_broadcast(), False)
		mac = MACAddress.broadcast()
		self.assertEqual(mac.is_ipv4_multicast(), False)
		self.assertEqual(mac.is_ipv6_multicast(), False)
		self.assertEqual(mac.is_multicast(), True)
		self.assertEqual(mac.is_unicast(), False)
		self.assertEqual(mac.is_universal(), False)
		self.assertEqual(mac.is_local(), True)
		self.assertEqual(mac.is_broadcast(), True)

