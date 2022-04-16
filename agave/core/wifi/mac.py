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
FRAME_SUB_TYPE_AUTHENTICATION = 11
FRAME_SUB_TYPE_DEAUTHENTICATION = 12

FRAME_TYPE_CONTROL_FRAME = 1
FRAME_SUB_TYPE_BLOCK_ACK_REQ = 8
FRAME_SUB_TYPE_BLOCK_ACK_RES = 9
FRAME_SUB_TYPE_REQUEST_TO_SEND = 11
FRAME_SUB_TYPE_CLEAR_TO_SEND = 12
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
		FRAME_SUB_TYPE_AUTHENTICATION: "Authentication",
		FRAME_SUB_TYPE_DEAUTHENTICATION: "Deauthentication",
		13: "Action",
	}),
	FRAME_TYPE_CONTROL_FRAME: ("Control Frame", {
		FRAME_SUB_TYPE_BLOCK_ACK_REQ: "Block ACK Req",
		FRAME_SUB_TYPE_BLOCK_ACK_RES: "Block ACK Res",
		FRAME_SUB_TYPE_REQUEST_TO_SEND: "Request-To-Send",
		FRAME_SUB_TYPE_CLEAR_TO_SEND: "Clear-To-Send",
		FRAME_SUB_TYPE_ACK: "Acknowledgment"
	}),
	FRAME_TYPE_DATA_FRAME: ("Data Frame", {
		0: "Data",
		4: "Null Function (No data)",
		8: "QoS Data",
		12: "QoS Null Function"
	})

}


class MAC_802_11(Frame):

	BYTEORDER = "little"

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
			frame.timestamp = buf.read_long()
			frame.beacon_interval = buf.read_short()
			frame.capabilities_information = buf.read_short()
		# parse tags
		frame.tags = TaggedParameter.parse_all(buf)
		return frame

	def write_to_buffer(self, buf: Buffer):
		if self.has_fixed_parameters:
			buf.write_long(self.timestamp)
			buf.write_short(self.beacon_interval)
			buf.write_short(self.capabilities_information)
		buf.write(b''.join(map(lambda x: bytes(x[1]), self.tags.items())))


"""
New models
"""

class MAC_802_11_Frame(Frame):
	"""Base class for MAC 802.11 Frames.

	Attributes:
		- fvts (int): frame version, type, and subtype.
		- flags (int): flags.
		- fcs (int): Frame Check Sequence, CRC32.

	"""
	__slots__ = ("fvts", "flags", "fcs")

	BYTEORDER = "little"

	TYPE = -1
	SUBTYPE = -1

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "MAC_802_11_Frame":
		mac = cls()
		mac.fvts = buf.read_byte()
		mac.flags = buf.read_byte()
		assert mac.TYPE == mac.type
		assert mac.SUBTYPE == mac.subtype
		return mac

	@property
	def subtype(self):
		return (self.fvts & 0xf0) >> 4

	@property
	def type(self):
		return (self.fvts & 0x0c) >> 2

	@property
	def version(self):
		return (self.fvts & 0x03) >> 2
	
	@property
	def flag_to_ds(self):
		return self.flags & 0x01 > 0

	@property
	def flag_from_ds(self):
		return self.flags & 0x02 > 0

	@property
	def flag_more_frag(self):
		return self.flags & 0x04 > 0

	@property
	def flag_retry(self):
		return self.flags & 0x08 > 0

	@property
	def flag_PWR_MGT(self):
		return self.flags & 0x10 > 0

	@property
	def flag_more_data(self):
		return self.flags & 0x20 > 0

	@property
	def flag_protected(self):
		return self.flags & 0x40 > 0

	@property
	def flag_order(self):
		return self.flags & 0x80 > 0


class ControlFrame(MAC_802_11_Frame):
	"""Base class for MAC 802.11 Control Frames.

	Attributes:
		- receiver (MACAddress): receiver address.
		- transmitter (MACAddress): transmitter address.

	"""
	__slots__ = ("duration_id", "receiver", "transmitter")

	TYPE = FRAME_TYPE_CONTROL_FRAME

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ControlFrame":
		mac = super().read_from_buffer(buf)
		mac.duration_id = buf.read_short()
		mac.receiver =  MACAddress(buf.read(6))
		return mac


class ClearToSend(ControlFrame):

	SUBTYPE = FRAME_SUB_TYPE_CLEAR_TO_SEND

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ClearToSend":
		mac = super().read_from_buffer(buf)
		mac.fcs =  buf.read_int()
		return mac


class Acknowledgment(ControlFrame):

	SUBTYPE = FRAME_SUB_TYPE_ACK

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Acknowledgment":
		mac = super().read_from_buffer(buf)
		mac.fcs =  buf.read_int()
		return mac


class RequestToSend(ControlFrame):

	SUBTYPE = FRAME_SUB_TYPE_REQUEST_TO_SEND

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "RequestToSend":
		mac = super().read_from_buffer(buf)
		mac.transmitter =  MACAddress(buf.read(6))
		mac.fcs = buf.read_int()
		return mac


class BlockACKRequest(ControlFrame):
	"""Block ACK request.

	Attributes:
		- control: block ACK control.
		- ssc: block ACK starting sequence control.

	"""
	__slots__ = ("control", "ssc", "bitmap")

	SUBTYPE = FRAME_SUB_TYPE_BLOCK_ACK_REQ

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "BlockACKRequest":
		mac = super().read_from_buffer(buf)
		mac.transmitter =  MACAddress(buf.read(6))
		mac.control = buf.read_short()
		mac.ssc = buf.read_short()
		mac.fcs = buf.read_int()
		return mac


class BlockACKResponse(ControlFrame):
	"""Block ACK response.

	Attributes:
		- control (int): block ACK control.
		- ssc (int): block ACK starting sequence control.
		- bitmap (int): block ACK bitmap.

	"""
	__slots__ = ("control", "ssc", "bitmap")

	SUBTYPE = FRAME_SUB_TYPE_BLOCK_ACK_RES

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "BlockACKResponse":
		mac = super().read_from_buffer(buf)
		mac.transmitter =  MACAddress(buf.read(6))
		mac.control = buf.read_short()
		mac.ssc = buf.read_short()
		mac.bitmap = buf.read_long()
		mac.fcs = buf.read_int()
		return mac


class ManagementFrame(MAC_802_11_Frame):
	"""Base class for MAC 802.11 Management Frames.

	Attributes:
		- destination (MACAddress): destination address.
		- source (MACAddress): source address.
		- BSSID (MACAddress): BSSID address.
		- sequence_control (int): sequence and fragment number.
		- data (Buffer): unparsed frame data, i.e., Wirless Management.
		- tags (List[TaggedParameter]): list of tag parameters.

	"""
	__slots__ = ("destination", "source", "BSSID", "sequence_control", "tags", "data")

	TYPE = FRAME_TYPE_MANAGEMENT_FRAME

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ManagementFrame":
		mac = super().read_from_buffer(buf)
		mac.destination = MACAddress(buf.read(6))
		mac.source = MACAddress(buf.read(6))
		mac.BSSID = MACAddress(buf.read(6))
		mac.sequence_control = buf.read_short()
		t = buf.read_remaining()
		mac.data = Buffer.from_bytes(t[:-4], byteorder="little")
		mac.fcs = int.from_bytes(t[-4:], byteorder="little")
		return mac


class Beacon(ManagementFrame):
	"""Beacon Frame. Sent periodically by AP to advertise their
	presence.

	Attributes:
		timestamp (int): timestamp.
		beacon_interval (int): beacon interval.
		capabilities (int): capabilities:

	"""
	__slots__ = ("timestamp", "beacon_interval", "capabilities")

	SUBTYPE = FRAME_SUB_TYPE_BEACON

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Beacon":
		mac = super().read_from_buffer(buf)
		mac.timestamp = mac.data.read_long()
		mac.beacon_interval = mac.data.read_short()
		mac.capabilities = mac.data.read_short()
		mac.tags = TaggedParameter.parse_all(mac.data)
		return mac


class ProbeResponse(Beacon):
	"""Probe Response Frame. Sent in response to probe requests,
	advertise the AP."""
	SUBTYPE = FRAME_SUB_TYPE_PROBE_RESPONSE


class ProbeRequest(Beacon):
	"""Probe Request Frame. Request APs to advertise."""
	SUBTYPE = FRAME_SUB_TYPE_PROBE_REQUEST

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ProbeRequest":
		mac = super().read_from_buffer(buf)
		mac.tags = TaggedParameter.parse_all(mac.data)
		return mac


class Authentication(ManagementFrame):
	"""Authentication. First step in network attachment. Hello exchange
	between AP and mobile station. 

	Attributes:
		- algorithm (int): algorithm used, 0 for OSA (Open System 
			Authentication). An other algorithm is Shared Key.
		- sequence (int): sequence of this frame (1 or 2 for OSA).
		- status (int): status code, 0 for success.

	"""
	__slots__ = ("algorithm", "sequence", "status")

	SUBTYPE = FRAME_SUB_TYPE_AUTHENTICATION

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Authentication":
		mac = super().read_from_buffer(buf)
		mac.algorithm = mac.data.read_short()
		mac.sequence = mac.data.read_short()
		mac.status = mac.data.read_short()
		return mac


class Deauthentication(ManagementFrame):
	"""Deauthentication frame. 

	Attributes:
		- reason (int): reason code.

	"""
	__slots__ = ("reason")

	SUBTYPE = FRAME_SUB_TYPE_DEAUTHENTICATION
	# Reason codes
	REASON_STA_IS_LEAVING_OR_HAS_LEFT = 3

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Deauthentication":
		mac = super().read_from_buffer(buf)
		mac.reason = mac.data.read_short()
		return mac


frame_class_map = {
	0x40: ProbeRequest,
	0x50: ProbeResponse,
	0x80: Beacon,
	0xb0: Authentication,
	0xc0: Deauthentication,
	0x84: BlockACKRequest,
	0x94: BlockACKResponse,
	0xb4: RequestToSend,
	0xc4: ClearToSend,
	0xd4: Acknowledgment
}


def next_frame_class(buf: Buffer) -> MAC_802_11_Frame:
	buf.mark()
	stv = buf.read_byte()
	klass = frame_class_map.get(stv, None)
	buf.restore()
	return klass

