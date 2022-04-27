import unittest
from agave.models.wifi.radiotap import RadioTapHeader
from agave.models.buffer import Buffer


class TestRadioTap(unittest.TestCase):

	packet = (
		b'\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00\x6a\xa5'
		b'\xa4\x18\x22\x01\x00\x00\x10\x02\x9e\x09\xa0\x00\xa6\x00\x00\x00\xa6\x00'
	)

	def test_read(self):
		frame = RadioTapHeader.from_bytes(self.packet)
		self.assertEqual(frame.revision, 0)
		self.assertEqual(frame.pad, 0)
		self.assertEqual(frame.length, 36)
		self.assertEqual(frame.bitmasks[0], 0xa000402f)
		self.assertEqual(len(frame.data), 24)

		