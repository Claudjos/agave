import unittest
from agave.models.ethernet import MACAddress
from agave.models.wifi.mac import WiFiMAC, Beacon, ProbeResponse, ProbeRequest
from agave.models.wifi.radiotap import RadioTapHeader
from agave.models.wifi.tags import TaggedParameters, SSID
from agv.wifi.jobs import Scanner
from typing import List, Tuple
from tests.dummy import DummyInterface


class TestScanner(unittest.TestCase):

	def test_process(self):
		"""Tests process beacons."""
		params = TaggedParameters()
		params.add(SSID.build("MyWifi"))
		bssid = MACAddress("bb:55:55:11:dd:00")
		beacon1 = Beacon.build(bssid, params, fcs=0)
		self.check_process(Scanner(None, DummyInterface(), [], None), [
			(beacon1, (bssid, "MyWifi")),
			(beacon1, None)
		])

	def test_ssid_filter(self):
		"""Tests SSID filter."""
		params = TaggedParameters()
		params.add(SSID.build("MyWifi"))
		params2 = TaggedParameters()
		params2.add(SSID.build("YourWifi"))
		bssid = MACAddress("bb:55:55:11:dd:00")
		st1 = MACAddress("aa:bb:cc:00:11:22")
		response = ProbeResponse.build(st1, bssid, params, fcs=0)
		beacon = Beacon.build(bssid, params2, fcs=0)
		job = Scanner(None, DummyInterface(), ["MyWifi"], None)
		self.check_process(job, [
			(response, (bssid, "MyWifi")),
			(response, None),
			(beacon, None)
		])
		t = job.get_others()
		self.assertEqual(t[0][1], "YourWifi")

	def check_process(self, job: Scanner, tests: List[Tuple[WiFiMAC, List[Tuple[MACAddress, str, WiFiMAC]]]]):
		radiotap = bytes(RadioTapHeader.build())
		for frame, result in tests:
			value = job.process(radiotap + bytes(frame), ())
			if value is not None:
				value = value[0], value[1]
			self.assertEqual(value, result)

	def test_probe_request(self):
		"""Tests process beacons."""
		params = TaggedParameters()
		params.add(SSID.build("SecretWifi"))
		params2 = TaggedParameters()
		params2.add(SSID.build("MyWifi"))
		st1 = MACAddress("aa:bb:cc:00:11:22")
		bssid = MACAddress("bb:55:55:11:dd:00")
		beacon = Beacon.build(bssid, params2, fcs=0)
		request1 = ProbeRequest.build(st1, params, fcs=0)
		request2 = ProbeRequest.build(st1, params2, fcs=0)
		radiotap = bytes(RadioTapHeader.build())
		job = Scanner(None, DummyInterface(), [], None)
		job.process(radiotap + bytes(request1), ())
		job.process(radiotap + bytes(request2), ())
		job.process(radiotap + bytes(beacon), ())
		t = job.get_requests()
		self.assertEqual(t[0], "SecretWifi")

