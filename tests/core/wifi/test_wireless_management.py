import unittest
from agave.core.wifi.mac import WirelessManagement
from agave.core.wifi.tags import PARAM_SSID_PARAMETER_SET
from agave.core.buffer import Buffer


class TestWirelessManagement(unittest.TestCase):

	message = (
		b'\x59\x01\xa6\x18\x22\x01\x00\x00\x64\x00\x31\x0c\x00\x0b\x53\x61'
		b'\x6e\x74\x6f\x72\x6f\x57\x69\x66\x69\x01\x08\x82\x84\x8b\x96\x12'
		b'\x24\x48\x6c'
	)

	def test_read(self):
		frame = WirelessManagement.from_bytes(self.message)
		self.assertEqual(frame.timestamp, 1245954048345)
		#self.assertEqual(frame.beacon_interval, )
		#self.assertEqual(frame.capabilities_information, )
		self.assertEqual(len(frame.tags.items()), 2)
		self.assertEqual(frame.tags[PARAM_SSID_PARAMETER_SET].SSID, "SantoroWifi")

