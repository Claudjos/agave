"""WiFi Jobs."""
from agave.core.ethernet import MACAddress
from agave.core.buffer import Buffer
from agave.core.wifi.mac import (
	FRAME_TYPE_DATA_FRAME,
	FRAME_TYPE_MANAGEMENT_FRAME,
	FRAME_SUB_TYPE_PROBE_RESPONSE,
	FRAME_SUB_TYPE_PROBE_REQUEST,
	FRAME_SUB_TYPE_BEACON,
	ProbeRequest,
	WiFiMAC
)
from agave.core.wifi.radiotap import RadioTapHeader, RadioTapField
from agave.core.wifi.tags import SSID, SupportedRates, TaggedParameters
from agave.utils.jobs import Job, SocketAddress
from agave.utils.interfaces import NetworkInterface
from typing import Tuple, List


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

	def process(self, data: bytes, address: SocketAddress) -> Tuple[MACAddress, str, WiFiMAC]:
		buf = Buffer.from_bytes(data, "little")
		rth = RadioTapHeader.read_from_buffer(buf)
		frame = WiFiMAC.from_buffer(buf)
		if frame.type == FRAME_TYPE_MANAGEMENT_FRAME:
			if (
				frame.subtype == FRAME_SUB_TYPE_PROBE_RESPONSE or
				frame.subtype == FRAME_SUB_TYPE_BEACON
			):
				t = (str(frame.transmitter), str(frame.tags.get(0).SSID))
				if t not in self._cache:
					self._cache.add(t)
					if self._ssids is not None:
						if t[1] in self._ssids:
							self._ssids.remove(t[1])
							if len(self._ssids) == 0:
								self.set_finished()
							return frame.transmitter, str(frame.tags.get(0).SSID), frame
						else:
							self._others.append((t[0], t[1], frame))
					else:
						return frame.transmitter, str(frame.tags.get(0).SSID), frame
			if frame.subtype == FRAME_SUB_TYPE_PROBE_REQUEST:
				t = str(frame.tags.get(0).SSID)
				if t != "" and t not in self._cache_req:
					self._cache_req.add(t)

	def get_others(self) -> List[Tuple[MACAddress, str, WiFiMAC]]:
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
	def build_probe_request(cls, transmitter: MACAddress, ssids: List[str], 
		tags: TaggedParameters = None, fields: List[RadioTapField] = None
		) -> bytes:
		"""Builds a probe request.

		Args:
			transmitter: transmitter station address.
			ssids: SSIDs to look for.
			tags: tagged parameters for 802.11 probe request.
			fields: fields for RadioTap header.
		
		Returns:
			A probe request as bytes.

		"""
		# RadioTap
		radiotap = RadioTapHeader.build(fields)
		# 802.11
		if tags is None:
			tags = TaggedParameters()
		tags.add(SSID.build(ssids[0] if len(ssids) == 1 else ""))
		tags.add(SupportedRates.build([0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c]))
		wmac = ProbeRequest.build(transmitter, tags)
		# Build the packet
		buf = Buffer.from_bytes(b'', byteorder="little")
		radiotap.write_to_buffer(buf)
		wmac.write_to_buffer(buf)
		return bytes(buf)


class StationsMapper(Job):

	__slots__ = ("_bssids", "_cache")

	def __init__(self, sock: "socket.socket", bssids: List[MACAddress], wait: float, **kwargs):
		super().__init__(sock, wait=wait, **kwargs)
		self._cache = set()
		self._bssids = bssids
		self.disable_loop()
		if wait is not None:
			self.set_deadline(wait)

	def process(self, data: bytes, address: SocketAddress) -> Tuple[MACAddress, MACAddress]:
		buf = Buffer.from_bytes(data, "little")
		rth = RadioTapHeader.read_from_buffer(buf)
		frame = WiFiMAC.from_buffer(buf)
		# gets BSSID and client
		output = []
		addr1 = addr2 = None
		if frame.type == FRAME_TYPE_DATA_FRAME:
			if frame.flags & 0x03:
				"""WDS. Not sure about this. I believe, in a simple case, receiver
				and transmitter are BSSs, with destination being a client connected to
				the receiver, while source is connected to the transmitter."""
				if self.add(frame.transmitter, frame.source):
					output.append((frame.transmitter, frame.source))
				if self.add(frame.receiver, frame.destination):
					output.append((frame.receiver, frame.destination))
			else:
				if self.add(frame.bssid, frame.destination):
					output.append((frame.bssid, frame.destination))
				if self.add(frame.bssid, frame.source):
					output.append((frame.bssid, frame.source))
		if output == []:
			return None
		else:
			return output

	def add(self, bssid: MACAddress, client: MACAddress) -> bool:
		# discard if BSSID and client are equal
		if bssid == client:
			return False
		# discard if BSSID is not in the target
		if self._bssids is not None and bssid not in self._bssids:
			return False
		# discard if multicast
		if client.is_multicast():
			return False
		# check cache
		key = f"{bssid}{client}"
		if not key in self._cache:
			self._cache.add(key)
			return True
		else:
			return False

