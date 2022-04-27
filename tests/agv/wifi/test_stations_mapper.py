import unittest
from agave.models.ethernet import MACAddress
from agave.models.wifi.mac import WiFiMAC, Null
from agave.models.wifi.radiotap import RadioTapHeader
from agv.wifi.jobs import StationsMapper
from typing import List, Tuple


class TestStationsMapper(unittest.TestCase):

	def test_ad_hoc(self):
		"""Tests process data frames in ad hoc mode or IBSS."""
		bssid = MACAddress("bb:55:55:11:dd:00")
		st1 = MACAddress("aa:bb:cc:00:11:22")
		st2 = MACAddress("aa:bb:cc:33:44:55")
		st3 = MACAddress("aa:bb:cc:66:77:88")
		broadcast = MACAddress.broadcast()
		self.check_process([
			(Null.build(st1, st2, bssid, flags=0), [(bssid, st1), (bssid, st2)]),
			(Null.build(st1, bssid, bssid, flags=0), None),
			(Null.build(st1, broadcast, bssid, flags=0), None),
			(Null.build(st3, bssid, bssid, flags=0), [(bssid, st3)]),
			(Null.build(st1, st3, bssid, flags=0), None),
		])

	def test_to_ds(self):
		"""Tests process data frames to ds."""
		bssid = MACAddress("bb:55:55:11:dd:00")
		st1 = MACAddress("aa:bb:cc:00:11:22")
		st2 = MACAddress("aa:bb:cc:33:44:55")
		st3 = MACAddress("aa:bb:cc:66:77:88")
		st4 = MACAddress("aa:bb:cc:99:aa:bb")
		broadcast = MACAddress.broadcast()
		self.check_process([
			(Null.build(bssid, st1, bssid, flags=1), [(bssid, st1)]),
			(Null.build(bssid, st1, broadcast, flags=1), None),
			(Null.build(bssid, st1, st2, flags=1), [(bssid, st2)]),
			(Null.build(bssid, st3, st4, flags=1), [(bssid, st4), (bssid, st3)]),
			(Null.build(bssid, st3, st4, flags=1), None),
		])

	def test_from_ds(self):
		"""Tests process data frames from ds."""
		bssid = MACAddress("bb:55:55:11:dd:00")
		st1 = MACAddress("aa:bb:cc:00:11:22")
		st2 = MACAddress("aa:bb:cc:33:44:55")
		st3 = MACAddress("aa:bb:cc:66:77:88")
		broadcast = MACAddress.broadcast()
		self.check_process([
			(Null.build(broadcast, bssid, bssid, flags=2), None),
			(Null.build(st1, bssid, bssid, flags=2), [(bssid, st1)]),
			(Null.build(st2, bssid, st3, flags=2), [(bssid, st2), (bssid, st3)]),
			(Null.build(st3, bssid, st2, flags=2), None),
		])

	def test_wds(self):
		"""Tests process data frames in WDS environment. Guess work."""
		bssid1 = MACAddress("bb:55:55:11:dd:00")
		bssid2 = MACAddress("bb:55:55:11:dd:11")
		st1 = MACAddress("aa:bb:cc:00:11:22")
		st2 = MACAddress("aa:bb:cc:33:44:55")
		self.check_process([
			(Null.build(bssid1, bssid2, st1, st2, flags=3), [(bssid2, st2), (bssid1, st1)]),
			(Null.build(bssid2, bssid1, st2, st1, flags=3), None),
		])
	
	def test_bssids_filter(self):
		"""Tests process data frames filtering the BSSID."""
		bssid1 = MACAddress("bb:55:55:11:dd:00")
		bssid2 = MACAddress("bb:55:55:11:dd:11")
		st1 = MACAddress("aa:bb:cc:00:11:22")
		st2 = MACAddress("aa:bb:cc:33:44:55")
		st3 = MACAddress("aa:bb:cc:66:77:88")
		st4 = MACAddress("aa:bb:cc:99:aa:bb")
		broadcast = MACAddress.broadcast()
		self.check_process([
			(Null.build(bssid1, st1, st2, flags=1), [(bssid1, st2), (bssid1, st1)]),
			(Null.build(bssid2, st3, st4, flags=1), None),
		], bssids=[bssid1])

	def check_process(self, tests: List[Tuple[WiFiMAC, List[Tuple[MACAddress, MACAddress]]]], bssids = None):
		job = StationsMapper(None, bssids, None)
		radiotap = bytes(RadioTapHeader.build())
		for frame, result in tests:
			self.assertEqual(job.process(radiotap + bytes(frame), ()), result)

