import unittest
from agave.core.ethernet import MACAddress
from agave.core.wifi.mac import (
	Acknowledgment, RequestToSend, BlockACKRequest, BlockACKResponse
)


class TestFrameControl(unittest.TestCase):

	acknowledgment = (
		b'\xd4\x00\x00\x00\xec\x10\x7b\xee\xe4\x05\x6e\x13\x2c\xe1'
	)

	request_to_send = (
		b'\xb4\x00\xb4\x00\x3c\xa0\x67\x2e\xc2\x22'
		b'\x00\x0c\xf6\xbe\x4d\x04\xb3\xe6\x16\xb6'
	)

	block_ack_req = (
		b'\x84\x00\xb0\x01\xec\x10\x7b\xee\xe4\x05\x00\x0c'
		b'\xf6\xbe\x4d\x04\x04\x00\xe0\x38\x11\x83\xd3\x2d'
	)

	block_ack_res = (
		b'\x94\x00\xa6\x01\x00\x0c\xf6\xbe\x4d\x04\xec\x10\x7b\xee\xe4\x05'
		b'\x05\x00\xe0\x38\x00\x00\x00\x00\x00\x00\x00\x00\x42\x59\xf7\x96'
	)

	def test_flavour_a(self):
		"""Tests flavor A frame - Acknowledgment."""
		frame = Acknowledgment.from_bytes(self.acknowledgment)
		# Checks parsing
		self.assertEqual(frame.duration_id, 0)
		self.assertEqual(frame.receiver, MACAddress("ec:10:7b:ee:e4:05"))
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.acknowledgment)

	def test_flavour_b(self):
		"""Tests flavor B frame - Request-To-Send."""
		frame = RequestToSend.from_bytes(self.request_to_send)
		# Checks parsing
		self.assertEqual(frame.duration_id, 180)
		self.assertEqual(frame.receiver, MACAddress("3c:a0:67:2e:c2:22"))
		self.assertEqual(frame.transmitter, MACAddress("00:0c:f6:be:4d:04"))
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.request_to_send)

	def test_block_ack_req(self):
		"""Tests Block ACK request."""
		frame = BlockACKRequest.from_bytes(self.block_ack_req)
		# Checks parsing
		self.assertEqual(frame.duration_id, 432)
		self.assertEqual(frame.receiver, MACAddress("ec:10:7b:ee:e4:05"))
		self.assertEqual(frame.transmitter, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.control, 4)
		self.assertEqual(frame.ssc, 0x38e0)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.block_ack_req)

	def test_block_ack_res(self):
		"""Tests Block ACK response."""
		frame = BlockACKResponse.from_bytes(self.block_ack_res)
		# Checks parsing
		self.assertEqual(frame.duration_id, 422)
		self.assertEqual(frame.receiver, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.transmitter, MACAddress("ec:10:7b:ee:e4:05"))
		self.assertEqual(frame.control, 5)
		self.assertEqual(frame.ssc, 0x38e0)
		self.assertEqual(frame.bitmap, 0)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.block_ack_res)
