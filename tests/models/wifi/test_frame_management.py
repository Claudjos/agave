import unittest
from agave.core.ethernet import MACAddress
from agave.core.wifi.mac import (
	Beacon, ProbeRequest
)


class TestFrameControl(unittest.TestCase):

	beacon = (
		b'\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x0c\xf6'
		b'\xbe\x4d\x04\x00\x0c\xf6\xbe\x4d\x04\x60\x36\x5a\xf1'
		b'\x50\x6d\x29\x00\x00\x00\x64\x00\x31\x0c\x00\x0b\x53'
		b'\x61\x6e\x74\x6f\x72\x6f\x57\x69\x66\x69\x01\x08\x82'
		b'\x84\x8b\x96\x12\x24\x48\x6c\x03\x01\x0b'
		b'\xff\xff\xff\xff'
	)

	probe_request = (
		b'\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff\xe8\x5a\x8b\xe2\x6a' 
		b'\x0b\xff\xff\xff\xff\xff\xff\xa0\x09\x00\x00\x01\x04\x02\x04' 
		b'\x0b\x16\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x03\x01\x0b' 
		b'\xff\xff\xff\xff'
	)

	def test_beacon(self):
		"""Tests Beacon."""
		frame = Beacon.from_bytes(self.beacon)
		# Checks parsing
		self.assertEqual(frame.duration_id, 0)
		self.assertEqual(frame.receiver, MACAddress("ff:ff:ff:ff:ff:ff"))
		self.assertEqual(frame.transmitter, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.sequence_control, 870 << 4)
		self.assertEqual(frame.timestamp, 177927680346)
		self.assertEqual(frame.beacon_interval, 100)
		self.assertEqual(frame.capabilities, 0x0c31)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.beacon)

	def test_probe_request(self):
		"""Tests Probe Request."""
		frame = ProbeRequest.from_bytes(self.probe_request)
		# Checks parsing
		self.assertEqual(frame.duration_id, 0)
		self.assertEqual(frame.receiver, MACAddress("ff:ff:ff:ff:ff:ff"))
		self.assertEqual(frame.transmitter, MACAddress("e8:5a:8b:e2:6a:0b"))
		self.assertEqual(frame.sequence_control, 154 << 4)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.probe_request)
