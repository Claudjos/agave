"""Temporary structure from 802.11 MAC frame."""
import struct
from agave.core.frame import Frame
from agave.core.buffer import Buffer, EndOfBufferError
from agave.core.ethernet import MACAddress
from .tags import TaggedParameter
from typing import List


FRAME_TYPE_MANAGEMENT_FRAME = 0
FRAME_SUB_TYPE_PROBE_REQUEST = 4
FRAME_SUB_TYPE_PROBE_RESPONSE = 5
FRAME_SUB_TYPE_BEACON = 8

FRAME_TYPE_CONTROL_FRAME = 1
FRAME_SUB_TYPE_ACK = 13

FRAME_TYPE_DATA_FRAME = 2


_all_map = {
	FRAME_TYPE_MANAGEMENT_FRAME: ("Management Frame", {
		0: "Association request",
		1: "Association response",
		2: "Reassociation request",
		3: "Reassociation response",
		FRAME_SUB_TYPE_PROBE_REQUEST: "Probe request",
		FRAME_SUB_TYPE_PROBE_RESPONSE: "Probe response",
		6: "Timing advertisement",
		7: "Reserved",
		FRAME_SUB_TYPE_BEACON: "Beacon",
		10: "Disassociation",
		11: "Authentication",
		12: "Deauthentication",
		16: "Action",
	}),
	FRAME_TYPE_CONTROL_FRAME: ("Control Frame", {
		8: "Block ACK Req",
		9: "Block ACK",
		11: "Request-To-Send",
		12: "Clear-To-Send",
		13: "Acknowledgment"
	}),
	FRAME_TYPE_DATA_FRAME: ("Data Frame", {
		0: "Data",
		4: "Null Function (No data)",
		8: "QoS Data",
		12: "QoS Null Function"
	})

}

_all_map = {
	FRAME_TYPE_MANAGEMENT_FRAME: ("Management Frame", {
		0: "Association request",
		1: "Association response",
		2: "Reassociation request",
		3: "Reassociation response",
		FRAME_SUB_TYPE_PROBE_REQUEST: "Probe request",
		FRAME_SUB_TYPE_PROBE_RESPONSE: "Probe response",
		6: "Timing advertisement",
		7: "Reserved",
		FRAME_SUB_TYPE_BEACON: "Beacon",
		10: "Disassociation",
		11: "Authentication",
		12: "Deauthentication",
		16: "Action",
	}),
	FRAME_TYPE_CONTROL_FRAME: ("Control Frame", {
		8: "Block ACK Req",
		9: "Block ACK",
		11: "Request-To-Send",
		12: "Clear-To-Send",
		13: "Acknowledgment"
	}),
	FRAME_TYPE_DATA_FRAME: ("Data Frame", {
		0: "Data",
		4: "Null Function (No data)",
		8: "QoS Data",
		12: "QoS Null Function"
	})

}


class MAC_802_11(Frame):

	def is_probe_request(self) -> bool:
		return self.subtype == FRAME_SUB_TYPE_PROBE_REQUEST and self.type == FRAME_TYPE_MANAGEMENT_FRAME

	def is_probe_response(self) -> bool:
		return self.subtype == FRAME_SUB_TYPE_PROBE_RESPONSE and self.type == FRAME_TYPE_MANAGEMENT_FRAME

	def is_beacon_frame(self) -> bool:
		return self.subtype == FRAME_SUB_TYPE_BEACON and self.type == FRAME_TYPE_MANAGEMENT_FRAME

	@classmethod
	def read_from_buffer(cls, buf):
		mac = cls()
		mac._frame_control_fields = buf.read_byte()
		mac._flags = buf.read_byte()
		mac.duration_id = buf.read_short()
		
		mac.receiver = mac.destination = mac.source = mac.transmitter = mac.BSSID = None

		# if data frame or management frame
		if mac.type == FRAME_TYPE_DATA_FRAME or mac.type == FRAME_TYPE_MANAGEMENT_FRAME:

			if mac.flag_to_ds is False and mac.flag_from_ds is False:
				mac.destination = MACAddress(buf.read(6))
				mac.source = MACAddress(buf.read(6))
				mac.BSSID = MACAddress(buf.read(6))
				mac.sequence_control = buf.read_short()
			elif mac.flag_to_ds is False and mac.flag_from_ds is True:
				mac.destination = MACAddress(buf.read(6))
				mac.BSSID = MACAddress(buf.read(6))
				mac.source = MACAddress(buf.read(6))
				mac.sequence_control = buf.read_short()
			elif mac.flag_to_ds is True and mac.flag_from_ds is False:
				mac.BSSID = MACAddress(buf.read(6))
				mac.source = MACAddress(buf.read(6))
				mac.destination = MACAddress(buf.read(6))
				mac.sequence_control = buf.read_short()
			else:
				mac.receiver = MACAddress(buf.read(6))
				mac.transmitter = MACAddress(buf.read(6))
				mac.destination = MACAddress(buf.read(6))
				mac.sequence_control = buf.read_short()
				mac.source = MACAddress(buf.read(6))

		if mac.type == FRAME_TYPE_CONTROL_FRAME:
			# parse differently
			mac.receiver = MACAddress(buf.read(6))
			#mac.sequence_control = buf.read_short()

		return mac

	def write_to_buffer(self, buf: Buffer):
		buf.write_byte(self._frame_control_fields)
		buf.write_byte(self._flags)
		buf.write_short(self.duration_id)

		# if data frame or management frame
		if self.type == 2 or self.type == 0:

			if self.flag_to_ds is False and self.flag_from_ds is False:
				buf.write(self.destination.packed)
				buf.write(self.source.packed)
				buf.write(self.BSSID.packed)
				buf.write_short(self.sequence_control)
			elif self.flag_to_ds is False and self.flag_from_ds is True:
				buf.write(self.destination.packed)
				buf.write(self.BSSID.packed)
				buf.write(self.source.packed)
				buf.write_short(self.sequence_control)
			elif self.flag_to_ds is True and self.flag_from_ds is False:
				buf.write(self.BSSID.packed)
				buf.write(self.source.packed)
				buf.write(self.destination.packed)
				buf.write_short(self.sequence_control)
			else:
				buf.write(self.receiver.packed)
				buf.write(self.transmitter.packed)
				buf.write(self.destination.packed)
				buf.write_short(self.sequence_control)
				buf.write(self.source.packed)

		if self.type == 1:
			buf.write(self.receiver.packed)
			#buf.write_short(self.sequence_control)


	@property
	def subtype(self):
		return (self._frame_control_fields & 0xf0) >> 4

	@property
	def type(self):
		return (self._frame_control_fields & 0x0c) >> 2

	@property
	def version(self):
		return (self._frame_control_fields & 0x03) >> 2
	
	@property
	def flag_to_ds(self):
		return self._flags & 0x01 > 0

	@property
	def flag_from_ds(self):
		return self._flags & 0x02 > 0

	@property
	def flag_more_frag(self):
		return self._flags & 0x04 > 0

	@property
	def flag_retry(self):
		return self._flags & 0x08 > 0

	@property
	def flag_PWR_MGT(self):
		return self._flags & 0x10 > 0

	@property
	def flag_more_data(self):
		return self._flags & 0x20 > 0

	@property
	def flag_protected(self):
		return self._flags & 0x40 > 0

	@property
	def flag_order(self):
		return self._flags & 0x80 > 0

	@classmethod
	def build_probe_request(cls, transmitter: MACAddress) -> "MAC_802_11":
		"""Builds a probe request."""
		frame = cls()
		"""
		frame.version = 0
		frame.type = FRAME_TYPE_MANAGEMENT_FRAME
		frame.subtype = FRAME_SUB_TYPE_PROBE_REQUEST
		"""
		frame._frame_control_fields = 0x40
		frame._flags = 0
		frame.duration_id = 0
		frame.destination = MACAddress("ff:ff:ff:ff:ff:ff")
		frame.source = transmitter
		frame.BSSID = MACAddress("ff:ff:ff:ff:ff:ff")
		# TODO, set a proper value
		frame.sequence_control = 0x00
		# Create
		return frame


class WirelessManagement(Frame):

	@classmethod
	def read_from_buffer(cls, buf: Buffer, with_fixed: bool = True) -> "WirelessManagement":
		frame = cls()
		frame.tags = {}
		frame.has_fixed_parameters = with_fixed
		if with_fixed:
			frame.timestamp = int.from_bytes(buf.read(8), byteorder="little")
			frame.beacon_interval = buf.read(2)
			frame.capabilities_information = buf.read(2)
		# parse tags
		frame.tags = TaggedParameter.parse_all(buf)
		return frame

	def write_to_buffer(self, buf: Buffer):
		if self.has_fixed_parameters:
			buf.write(self.timestamp.to_bytes(8, byteorder="little"))
			buf.write(self.beacon_interval)
			buf.write(self.capabilities_information)
		buf.write(b''.join(map(lambda x: bytes(x[1]), self.tags.items())))

