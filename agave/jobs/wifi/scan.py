"""Simple job to actively scan for APs.

The module provides also a main to be executed as script.

Usage:
	python3 -m agave.jobs.wifi.scan <interface> [[SSID], ...]
	python3 -m agave.jobs.wifi.scan phy0.mon
	python3 -m agave.jobs.wifi.scan phy0.mon MyWiFi
	
"""
import socket
from agave.core.ethernet import MACAddress
from agave.core.buffer import Buffer
from agave.core.wifi.radiotap import RadioTapHeader, RadioTapField
from agave.core.wifi.mac import MAC_802_11, WirelessManagement
from agave.core.wifi.tags import SSID, SupportedRates, TaggedParameter
from agave.utils.jobs import Job, SocketAddress
from agave.utils.interfaces import NetworkInterface
from typing import Tuple, List, Dict


class Scanner(Job):

	__slots__ = ("_cache", "_ssids", "_requests", "_others", "_cache_req")

	def __init__(self, sock: "socket.socket", interface: NetworkInterface, 
		ssids: List[str], request: bytes, repeat: int = 3, **kwargs):
		super().__init__(sock, **kwargs)
		self._cache = set()
		self._ssids = ssids if len(ssids) > 0 else None
		self._requests = self.generate_stream(request, interface.name, repeat)
		self._others = []
		self._cache_req = set()

	def generate_stream(self, request: bytes, interface: str, repeat: int):
		for _ in range(0, repeat):
			yield request, (interface, 0)
		return

	def loop(self) -> bool:
		for message in self._requests:
			self.sock.sendto(*message)
			return True
		return False

	def process(self, data: bytes, address: SocketAddress) -> Tuple[MACAddress, str, WirelessManagement]:
		buf = Buffer.from_bytes(data[:-4], "little")
		rth = RadioTapHeader.read_from_buffer(buf)
		frame = MAC_802_11.read_from_buffer(buf)
		if frame.is_probe_response() or frame.is_beacon_frame():
			wm = WirelessManagement.read_from_buffer(buf)
			t = (str(frame.BSSID), str(wm.tags[0].SSID))
			if t not in self._cache:
				self._cache.add(t)
				if self._ssids is not None:
					if t[1] in self._ssids:
						self._ssids.remove(t[1])
						if len(self._ssids) == 0:
							self.set_finished()
						return frame.BSSID, str(wm.tags[0].SSID), wm
					else:
						self._others.append((t[0], t[1], wm))
				else:
					return frame.BSSID, str(wm.tags[0].SSID), wm
		if frame.is_probe_request():
			wm = WirelessManagement.read_from_buffer(buf, with_fixed=False)
			t = str(wm.tags[0].SSID)
			if t != "" and t not in self._cache_req:
				self._cache_req.add(t)

	def get_others(self) -> List[Tuple[MACAddress, str, WirelessManagement]]:
		"""Returns info about APs whose beacon or response where received,
		but are not in the SSID list."""
		return self._others

	def get_requests(self) -> List[str]:
		"""Returns the SSID found in received probe requests, but for which
		no beacon or probe response was sniffed. The SSIDs in the SSID list
		are not considered."""
		output = []
		exclude_ssids = list(map(lambda x: x[1], self.get_others())) + \
			list(map(lambda x: x[1], self._cache)) + \
			[] if self._ssids is None else self._ssids
		for ssid in self._cache_req:
			if ssid not in exclude_ssids:
				output.append(ssid)
		return output

	@classmethod
	def build_probe_request(cls, ssids: List[str], tags: Dict[int, TaggedParameter] = None, 
		fields: List[RadioTapField] = None) -> bytes:
		"""Builds a probe request.

		Args:
			ssids: SSIDs to look for.
			tags: tagged parameter for 802.11 probe request.
			fields: fields for RadioTap header.
		
		Returns:
			A probe request as bytes.

		"""
		# RadioTap
		radiotap = RadioTapHeader.build(fields)
		# 802.11 MAC
		mac = MAC_802_11.build_probe_request(interface.mac)
		mac.sequence_control = 1900
		# Wireless Management
		wm = WirelessManagement()
		wm.has_fixed_parameters = False
		wm.tags = {}
		wm.tags[0] = SSID(0, 0, ssids[0].encode() if len(ssids) == 1 else b'')
		wm.tags[1] = SupportedRates.build([0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c])
		if tags is not None:
			for k, v in tags.items():
				wm.tags[k] = v
		# Build the packet
		buf = Buffer.from_bytes(b'', byteorder="little")
		radiotap.write_to_buffer(buf)
		mac.write_to_buffer(buf)
		wm.write_to_buffer(buf)
		return bytes(buf)


if __name__ == "__main__":

	import sys


	# Check input
	if len(sys.argv) < 2:
		print("Too few parameters.")
		exit(0)
	# Parse input
	interface = NetworkInterface.get_by_name(sys.argv[1])
	ssids = [sys.argv[i] for i in range(2, len(sys.argv))]
	# Creates socket
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	sock.bind((interface.name, 0))
	# Create job
	job = Scanner(sock, interface, ssids, Scanner.build_probe_request(ssids), 
		repeat=3, interval=0.1, wait=10 if len(ssids) == 0 else 1)
	# Stream job results
	for mac, ssid, settings in job.stream():
		print(f"{ssid} ({mac})")
	# Other
	others = job.get_others()
	if len(others) > 0:
		print("Other APs found:")
		for mac, ssid, settings in others:
			print(f"\t{ssid} ({mac})")
	# Requested
	reqs = job.get_requests()
	if len(reqs) > 0:
		print("SSID requested by others:")
		for ssid in reqs:
			print("\t", ssid)

