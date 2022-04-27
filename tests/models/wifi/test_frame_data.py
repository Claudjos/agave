import unittest
from agave.models.ethernet import MACAddress
from agave.models.wifi.mac import QoSNull, QoSData, Data


class TestFrameData(unittest.TestCase):

	data = (
		b'\x08\x42\x00\x00\x01\x00\x5e\x00\x00\x01\x00\x0c\xf6\xbe'
		b'\x4d\x04\x00\x0c\xf6\xbe\x4d\x04\xc0\xb2\x5d\x18\x00\x60'
		b'\x00\x00\x00\x00'
		b'\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\xc0\x00\x1c'
		b'\x32\xa2\x00\x00\x01\x02\xe5\xd3\xc0\xa8\x00\x01\xe0\x00\x00\x01'
		b'\x11\x64\xee\x9b\x00\x00\x00\x00\x44\xcb\xa0\xa4\x9f\x37\xd5\x0d'
		b'\xc9\xd8\xc7\xb7'
	)

	qos_data = (
		b'\x88\x42\x24\x00\x7c\xf9\x0e\x48\xe4\xc4\x00\x0c\xf6\xbe'
		b'\x4d\x04\x00\x0c\xf6\xbe\x4d\x04\x90\xb6\x00\x00\x68\x0b'
		b'\x00\x20\x00\x00\x00\x00'
		b'\x09\x62\x25\xb3\xd2\x55\x29\x98\xbc\xd1\xd9\xf9\xe8\x3f\xe1\xe7\xd0'
		b'\xf8\x49\x21\x82\xee\x1e\xa3\x3b\x70\x10\xd1\x14\xcb\xa2\x33\x2d\x57'
		b'\xd9\x1a\xbc\x07\xa9\xc7\x96\xbd\x59\x86\x87\x0c\x9d\xef\xa5\x13\xd3'
		b'\x26\x6b\xab\x9c\x7c\x60\x69\x6e\x96\xdc\x6d\xfb\x3c\x19\xb2\xde\xcc'
		b'\x07\x67\xce\xe7'
	)

	qos_null = (
		b'\xc8\x01\x3a\x01\x00\x0c\xf6\xbe\x4d\x04\xec\x10\x7b'
		b'\xee\xe4\x05\x00\x0c\xf6\xbe\x4d\x04\xc0\x43\x00\x00'
		b'\xaf\xdc\x8b\x6e'
	)

	qos_null_2 = (
		b'\xc8\x11\x00\x00\x00\x0c\xf6\xbe\x4d\x04\x3c\xa0\x67'
		b'\x2e\xc2\x22\x00\x0c\xf6\xbe\x4d\x04\x00\x00\x07\x00'
	)

	def test_data(self):
		"""Tests Data."""
		frame = Data.from_bytes(self.data)
		# Checks parsing
		self.assertEqual(frame.duration_id, 0)
		self.assertEqual(frame.flag_protected, True)
		self.assertEqual(frame.flag_to_ds, False)
		self.assertEqual(frame.flag_from_ds, True)
		self.assertEqual(frame.receiver, MACAddress("01:00:5e:00:00:01"))
		self.assertEqual(frame.transmitter, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.destination, MACAddress("01:00:5e:00:00:01"))
		self.assertEqual(frame.source, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.bssid, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.sequence_control, 2860 << 4)
		self.assertEqual(frame.ccmp_params, 0x00006000185d)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.data)

	def test_qos_data(self):
		"""Tests QoS Data."""
		frame = QoSData.from_bytes(self.qos_data)
		# Checks parsing
		self.assertEqual(frame.duration_id, 36)
		self.assertEqual(frame.flag_protected, True)
		self.assertEqual(frame.flag_to_ds, False)
		self.assertEqual(frame.flag_from_ds, True)
		self.assertEqual(frame.receiver, MACAddress("7c:f9:0e:48:e4:c4"))
		self.assertEqual(frame.transmitter, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.destination, MACAddress("7c:f9:0e:48:e4:c4"))
		self.assertEqual(frame.source, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.bssid, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.sequence_control, 2921 << 4)
		self.assertEqual(frame.qos_control, 0)
		self.assertEqual(frame.ccmp_params, 0x000000020000b68)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.qos_data)

	def test_read_qos_null(self):
		"""Tests QoS Null."""
		frame = QoSNull.from_bytes(self.qos_null)
		# Checks parsing
		self.assertEqual(frame.duration_id, 314)
		self.assertEqual(frame.flag_to_ds, True)
		self.assertEqual(frame.flag_from_ds, False)
		self.assertEqual(frame.receiver, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.transmitter, MACAddress("ec:10:7b:ee:e4:05"))
		self.assertEqual(frame.destination, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.source, MACAddress("ec:10:7b:ee:e4:05"))
		self.assertEqual(frame.bssid, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.sequence_control, 1084 << 4)
		self.assertEqual(frame.qos_control, 0x0000)
		# Checks writing by rewriting the frame
		self.assertEqual(bytes(frame), self.qos_null)

	def test_read_qos_null_2(self):
		"""Tests QoS Null."""
		frame = QoSNull.from_bytes(self.qos_null_2)
		self.assertEqual(frame.duration_id, 0)
		self.assertEqual(frame.flag_to_ds, True)
		self.assertEqual(frame.flag_from_ds, False)
		self.assertEqual(frame.receiver, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.transmitter, MACAddress("3c:a0:67:2e:c2:22"))
		self.assertEqual(frame.destination, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.source, MACAddress("3c:a0:67:2e:c2:22"))
		self.assertEqual(frame.bssid, MACAddress("00:0c:f6:be:4d:04"))
		self.assertEqual(frame.sequence_control, 0)
		self.assertEqual(frame.qos_control, 0x0007)

