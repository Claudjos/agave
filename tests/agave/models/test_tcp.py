import unittest
from agave.models.tcp import TCP
from agave.models.ip import IPv4, PROTO_TCP
from ipaddress import IPv4Address


class TestTCP(unittest.TestCase):

	syn_packet = (
		b'\xda\xee\x13\x88\x65\x82\x7a\x41\x00\x00\x00\x00\xa0\x02\xff\xd7'
		b'\xfe\x30\x00\x00\x02\x04\xff\xd7\x04\x02\x08\x0a\x89\x66\x65\x4f'
		b'\x00\x00\x00\x00\x01\x03\x03\x07'
	)

	data_packet = (
		b'\x00\x50\xdd\x76\x79\x87\x1a\x37\x60\xc9\xf6\xa6\x50\x18'
		b'\x12\x48\x12\xc1\x00\x00\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x32'
		b'\x30\x34\x20\x4e\x6f\x20\x43\x6f\x6e\x74\x65\x6e\x74\x0d\x0a\x44'
		b'\x61\x74\x65\x3a\x20\x53\x75\x6e\x2c\x20\x30\x31\x20\x4d\x61\x79'
		b'\x20\x32\x30\x32\x32\x20\x31\x39\x3a\x33\x36\x3a\x32\x36\x20\x47'
		b'\x4d\x54\x0d\x0a\x53\x65\x72\x76\x65\x72\x3a\x20\x41\x70\x61\x63'
		b'\x68\x65\x2f\x32\x2e\x34\x2e\x31\x38\x20\x28\x55\x62\x75\x6e\x74'
		b'\x75\x29\x0d\x0a\x58\x2d\x4e\x65\x74\x77\x6f\x72\x6b\x4d\x61\x6e'
		b'\x61\x67\x65\x72\x2d\x53\x74\x61\x74\x75\x73\x3a\x20\x6f\x6e\x6c'
		b'\x69\x6e\x65\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a'
		b'\x20\x63\x6c\x6f\x73\x65\x0d\x0a\x0d\x0a'
	)

	fin_packet = (
		b'\x00\x50\xdd\x76\x79\x87\x1a\xcb\x60\xc9\xf6\xa6\x50\x11\x12\x48'
		b'\x7f\xf7\x00\x00'
	)

	def test_parse_syn(self):
		packet = TCP.from_bytes(self.syn_packet)
		self.assertEqual(packet.source, 56046)
		self.assertEqual(packet.destination, 5000)
		self.assertEqual(packet.sequence_number, 1703049793)
		self.assertEqual(packet.ack_number, 0)
		self.assertEqual(packet.data_offset, 10)
		self.assertEqual(packet.ns, False)
		self.assertEqual(packet.cwr, False)
		self.assertEqual(packet.ece, False)
		self.assertEqual(packet.urg, False)
		self.assertEqual(packet.ack, False)
		self.assertEqual(packet.psh, False)
		self.assertEqual(packet.syn, True)
		self.assertEqual(packet.fin, False)
		self.assertEqual(packet.window_size, 65495)
		self.assertEqual(packet.checksum, 0xfe30)
		self.assertEqual(packet.urgent_pointer, 0)
		self.assertEqual(packet._options, self.syn_packet[20:])
		self.assertEqual(bytes(packet), self.syn_packet)

	def test_flags_data_packet(self):
		packet = TCP.from_bytes(self.data_packet)
		self.assertEqual(packet.data_offset, 5)
		self.assertEqual(packet.ns, False)
		self.assertEqual(packet.cwr, False)
		self.assertEqual(packet.ece, False)
		self.assertEqual(packet.urg, False)
		self.assertEqual(packet.ack, True)
		self.assertEqual(packet.psh, True)
		self.assertEqual(packet.syn, False)
		self.assertEqual(packet.fin, False)

	def test_flags_fin_packet(self):
		packet = TCP.from_bytes(self.fin_packet)
		self.assertEqual(packet.data_offset, 5)
		self.assertEqual(packet.ns, False)
		self.assertEqual(packet.cwr, False)
		self.assertEqual(packet.ece, False)
		self.assertEqual(packet.urg, False)
		self.assertEqual(packet.ack, True)
		self.assertEqual(packet.psh, False)
		self.assertEqual(packet.syn, False)
		self.assertEqual(packet.fin, True)

	def test_checksum_data_packet(self):
		packet = TCP.from_bytes(self.data_packet)
		payload = self.data_packet[packet.data_offset*4:]
		pseudo_header = IPv4.build_pseudo_header(
			IPv4Address("35.232.111.17"),
			IPv4Address("192.168.0.105"),
			PROTO_TCP,
			len(self.data_packet)
		)
		self.assertTrue(packet.is_checksum_valid(pseudo_header, payload))

	def test_checksum_fin_packet(self):
		packet = TCP.from_bytes(self.fin_packet)
		payload = b''
		pseudo_header = IPv4.build_pseudo_header(
			IPv4Address("192.168.0.105"),
			IPv4Address("35.232.111.17"),
			PROTO_TCP,
			len(self.fin_packet)
		)
		self.assertTrue(packet.is_checksum_valid(pseudo_header, payload))

	def test_set_get_data_offset(self):
		packet = TCP()
		packet._offset_ns = 0
		packet.data_offset = 10
		self.assertEqual(packet.data_offset, 10)

