import unittest
from agave.core.arp import *
from agave.core.buffer import Buffer


class TestARP(unittest.TestCase):

	arp_header = (
		b'\x00\x01\x08\x00\x06\x04\x00\x02\x00\x1c\xf2\xbe\x4d\x14'
		b'\xc0\xa8\x00\x01\x3c\xaa\x67\x22\x02\x22\xc0\xa8\x00\x69'
	)

	def test_read(self):
		packet = ARP.read_from_buffer(Buffer.from_bytes(self.arp_header))
		self.assertEqual(packet.hardware_type, HARDWARE_TYPE_ETHERNET)
		self.assertEqual(packet.protocol_type, PROTOCOL_TYPE_IP)
		self.assertEqual(packet.hardware_addr_len, ADDRESS_LEN_ETHERNET)
		self.assertEqual(packet.protocol_addr_len, ADDRESS_LEN_IP)
		self.assertEqual(packet.operation, OPERATION_REPLY)
		self.assertEqual(packet.sender_hardware_address, 
			b'\x00\x1c\xf2\xbe\x4d\x14')
		self.assertEqual(packet.sender_protocol_address,
			IPv4Address("192.168.0.1").packed)
		self.assertEqual(packet.target_hardware_address,
			b'\x3c\xaa\x67\x22\x02\x22')
		self.assertEqual(packet.target_protocol_address,
			IPv4Address("192.168.0.105").packed)

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = ARP.read_from_buffer(Buffer.from_bytes(self.arp_header))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.arp_header)

