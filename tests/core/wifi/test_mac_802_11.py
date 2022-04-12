import unittest
from agave.core.ethernet import MACAddress
from agave.core.wifi.mac import MAC_802_11
from agave.core.buffer import Buffer


class TestMAC_802_11(unittest.TestCase):

	packet = (
		b'\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x0c'
		b'\xf6\xbe\x4d\x04\x00\x0c\xf6\xbe\x4d\x04\x90\x95'
	)

	def test_read(self):
		frame = MAC_802_11.from_bytes(self.packet)
		self.assertEqual(frame.version, 0)
		self.assertEqual(frame.type, 0)
		self.assertEqual(frame.subtype, 8)
		self.assertEqual(frame.duration_id, 0)
		self.assertEqual(frame.destination, MACAddress("ff:ff:ff:ff:ff:ff"))
		self.assertEqual(frame.source, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.BSSID, MACAddress("00:0c:f6:be:4d:04"))

		