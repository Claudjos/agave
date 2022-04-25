"""Temporary structure from 802.11 MAC frame."""
import struct
from agave.core.frame import Frame
from agave.core.buffer import Buffer, EndOfBufferError
from agave.core.ethernet import MACAddress
from .tags import TaggedParameter
from typing import List


FRAME_TYPE_MANAGEMENT_FRAME = 0
FRAME_SUB_TYPE_ASSOCIATION_REQUEST = 0
FRAME_SUB_TYPE_ASSOCIATION_RESPONSE = 1
FRAME_SUB_TYPE_PROBE_REQUEST = 4
FRAME_SUB_TYPE_PROBE_RESPONSE = 5
FRAME_SUB_TYPE_BEACON = 8
FRAME_SUB_TYPE_DEASSOCIATION = 10
FRAME_SUB_TYPE_AUTHENTICATION = 11
FRAME_SUB_TYPE_DEAUTHENTICATION = 12
FRAME_SUB_TYPE_ACTION = 13

FRAME_TYPE_CONTROL_FRAME = 1
FRAME_SUB_TYPE_BLOCK_ACK_REQ = 8
FRAME_SUB_TYPE_BLOCK_ACK_RES = 9
FRAME_SUB_TYPE_POWER_SAVE_POLL = 10
FRAME_SUB_TYPE_REQUEST_TO_SEND = 11
FRAME_SUB_TYPE_CLEAR_TO_SEND = 12
FRAME_SUB_TYPE_ACK = 13
FRAME_SUB_TYPE_CF_END = 14

FRAME_TYPE_DATA_FRAME = 2
FRAME_SUB_TYPE_DATA = 0
FRAME_SUB_TYPE_NULL = 4
FRAME_SUB_TYPE_QOS_DATA = 8
FRAME_SUB_TYPE_QOS_NULL = 12


_all_map = {
	FRAME_TYPE_MANAGEMENT_FRAME: ("Management Frame", {
		FRAME_SUB_TYPE_ASSOCIATION_REQUEST: "Association request",
		FRAME_SUB_TYPE_ASSOCIATION_RESPONSE: "Association response",
		2: "Reassociation request",
		3: "Reassociation response",
		FRAME_SUB_TYPE_PROBE_REQUEST: "Probe request",
		FRAME_SUB_TYPE_PROBE_RESPONSE: "Probe response",
		6: "Timing advertisement",
		7: "Reserved",
		FRAME_SUB_TYPE_BEACON: "Beacon",
		FRAME_SUB_TYPE_DEASSOCIATION: "Disassociation",
		FRAME_SUB_TYPE_AUTHENTICATION: "Authentication",
		FRAME_SUB_TYPE_DEAUTHENTICATION: "Deauthentication",
		FRAME_SUB_TYPE_ACTION: "Action",
	}),
	FRAME_TYPE_CONTROL_FRAME: ("Control Frame", {
		FRAME_SUB_TYPE_BLOCK_ACK_REQ: "Block ACK Req",
		FRAME_SUB_TYPE_BLOCK_ACK_RES: "Block ACK Res",
		FRAME_SUB_TYPE_POWER_SAVE_POLL: "Power Save Poll",
		FRAME_SUB_TYPE_REQUEST_TO_SEND: "Request-To-Send",
		FRAME_SUB_TYPE_CLEAR_TO_SEND: "Clear-To-Send",
		FRAME_SUB_TYPE_ACK: "Acknowledgment",
		FRAME_SUB_TYPE_CF_END: "CF-End"
	}),
	FRAME_TYPE_DATA_FRAME: ("Data Frame", {
		FRAME_SUB_TYPE_DATA: "Data",
		FRAME_SUB_TYPE_NULL: "Null",
		FRAME_SUB_TYPE_QOS_DATA: "QoS Data",
		FRAME_SUB_TYPE_QOS_NULL: "QoS Null"
	})

}


"""
New models
"""

class WiFiMAC(Frame):
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
	def read_from_buffer(cls, buf: Buffer) -> "WiFiMAC":
		mac = cls()
		mac.fvts = buf.read_byte()
		mac.flags = buf.read_byte()
		assert mac.TYPE == mac.type
		assert mac.SUBTYPE == mac.subtype
		return mac

	def write_to_buffer(self, buf: Buffer):
		buf.write_byte(self.fvts)
		buf.write_byte(self.flags)

	@classmethod
	def build(cls, flags: int = 0) -> "WiFiMAC":
		mac = cls()
		mac.fvts = (cls.TYPE << 2) | (cls.SUBTYPE << 4)
		mac.flags = flags
		return mac

	@property
	def subtype(self):
		return (self.fvts & 0xf0) >> 4

	@property
	def type(self):
		return (self.fvts & 0x0c) >> 2

	@property
	def version(self):
		return (self.fvts & 0x03)
	
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

	@classmethod
	def from_buffer(cls, buf: Buffer) -> "WiFiMAC":
		klass = next_frame_class(buf)
		if klass is None:
			return None
		else:
			return klass.read_from_buffer(buf)


class ControlFrame(WiFiMAC):
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


class PowerSavePoll(ControlFrame):
	"""PowerSavePoll frame."""
	SUBTYPE = FRAME_SUB_TYPE_POWER_SAVE_POLL

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "PowerSavePoll":
		mac = super().read_from_buffer(buf)
		mac.transmitter =  MACAddress(buf.read(6))
		mac.fcs = buf.read_int()
		return mac


class CFEnd(ControlFrame):
	"""CF-End frame."""
	SUBTYPE = FRAME_SUB_TYPE_CF_END

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "CFEnd":
		mac = super().read_from_buffer(buf)
		mac.transmitter =  MACAddress(buf.read(6))
		mac.fcs = buf.read_int()
		return mac


class ManagementFrame(WiFiMAC):
	"""Base class for MAC 802.11 Management Frames.

	Attributes:
		- receiver (MACAddress): receiver address.
		- transmitter (MACAddress): transmitter address.
		- destination (MACAddress): destination address.
		- sequence_control (int): sequence and fragment number.
		- data (Buffer): unparsed frame data, i.e., Wireless Management.
		- tags (List[TaggedParameter]): list of tag parameters.

	"""
	__slots__ = ("receiver", "transmitter", "destination", "sequence_control", 
		"tags", "data", "duration_id")

	TYPE = FRAME_TYPE_MANAGEMENT_FRAME

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ManagementFrame":
		mac = super().read_from_buffer(buf)
		mac.duration_id = buf.read_short()
		mac.receiver = MACAddress(buf.read(6))
		mac.transmitter = MACAddress(buf.read(6))
		mac.destination = MACAddress(buf.read(6))
		mac.sequence_control = buf.read_short()
		t = buf.read_remaining()
		mac.data = Buffer.from_bytes(t[:-4], byteorder="little")
		mac.fcs = int.from_bytes(t[-4:], byteorder="little")
		return mac

	def write_to_buffer(self, buf: Buffer):
		super().write_to_buffer(buf)
		buf.write_short(self.duration_id)
		buf.write(self.receiver.packed)
		buf.write(self.transmitter.packed)
		buf.write(self.destination.packed)
		buf.write_short(self.sequence_control)
		buf.write(bytes(self.data))
		#buf.write_int(self.fcs)

	@classmethod
	def build(cls, receiver: MACAddress, transmitter: MACAddress, 
		destination: MACAddress, duration_id: int = 8252, sequence_control: int = 0, 
		**kwargs) -> "ManagementFrame":
		"""Builder.

		Args:
			**kwargs: keyword arguments for WiFiMAC.build.

		"""
		mac = super().build(**kwargs)
		mac.duration_id = duration_id
		mac.receiver = receiver
		mac.transmitter = transmitter
		mac.destination = destination
		mac.sequence_control = sequence_control
		mac.data = Buffer.from_bytes(b'', byteorder="little")
		mac.fcs = 0
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


class ProbeRequest(ManagementFrame):
	"""Probe Request Frame. Request APs to advertise."""
	SUBTYPE = FRAME_SUB_TYPE_PROBE_REQUEST

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ProbeRequest":
		mac = super().read_from_buffer(buf)
		mac.tags = TaggedParameter.parse_all(mac.data)
		return mac

	def write_to_buffer(self, buf: Buffer) -> "ProbeRequest":
		self.data.write(b''.join(map(lambda x: bytes(x[1]), self.tags.items())))
		super().write_to_buffer(buf)

	@classmethod
	def build(cls, transmitter: MACAddress, params: List[TaggedParameter], 
		**kwargs) -> "ProbeRequest":
		"""Builder.

		Args:
			transmitter: transmitter station address.
			params: list of parameters.
			kwargs; keyword argument for ManagementFrame.build.
		"""
		destination = MACAddress.broadcast()
		x = super().build(destination, transmitter, destination)
		x.tags = {k: v for k,v in map(lambda p: (p.number, p), params)}
		return x


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

	def write_to_buffer(self, buf: Buffer):
		self.data.write_short(self.reason)
		super().write_to_buffer(buf)

	@classmethod
	def build(cls, station: MACAddress, ap: MACAddress, reason: int = 3, **kwargs) -> "Deauthentication":
		mac = super().build(ap, station, ap, **kwargs)
		mac.reason = reason
		return mac


class Disassociation(Deauthentication):
	"""Disassociation frame."""
	SUBTYPE = FRAME_SUB_TYPE_DEASSOCIATION


class AssociationRequest(ManagementFrame):
	"""Association request frame. 

	Attributes:
		- capabilities (int): capabilities.
		- listen_interval (int): listen interval.

	"""
	__slots__ = ("capabilities", "listen_interval")

	SUBTYPE = FRAME_SUB_TYPE_ASSOCIATION_REQUEST

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "AssociationRequest":
		mac = super().read_from_buffer(buf)
		mac.capabilities = mac.data.read_short()
		mac.listen_interval = mac.data.read_short()
		mac.tags = TaggedParameter.parse_all(buf)
		return mac


class AssociationResponse(ManagementFrame):
	"""Association response frame. 

	Attributes:
		- capabilities (int): capabilities.
		- status_code (int): status code.
		- association_id (int): association id.

	"""
	__slots__ = ("capabilities", "status_code", "association_id")

	SUBTYPE = FRAME_SUB_TYPE_ASSOCIATION_RESPONSE

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "AssociationResponse":
		mac = super().read_from_buffer(buf)
		mac.capabilities = mac.data.read_short()
		mac.status_code = mac.data.read_short()
		mac.association_id = mac.data.read_short()
		mac.tags = TaggedParameter.parse_all(buf)
		return mac


class Action(ManagementFrame):
	"""Action response frame. 

	Attributes:
		- category (int): category code.
		- action (int): action code.

	Todos:
		* parse fixed parameters. Vary on category/action.

	"""
	__slots__ = ("category", "action")

	SUBTYPE = FRAME_SUB_TYPE_ACTION

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Action":
		mac = super().read_from_buffer(buf)
		mac.category = mac.data.read_byte()
		mac.action = mac.data.read_byte()
		# Parse other fields.
		return mac


class DataFrame(WiFiMAC):
	"""Base class for MAC 802.11 Data Frames.

	Attributes:
		- receiver (MACAddress): receiver address.
		- transmitter (MACAddress): transmitter address.
		- destination (MACAddress): destination address.
		- source (MACAddress): source address.
		- sequence_control (int): sequence and fragment number.
		- data (Buffer): unparsed frame data, i.e., Wireless Management.

	"""
	__slots__ = ("duration_id", "receiver", "transmitter", "destination", "source", "sequence_control", "data")

	TYPE = FRAME_TYPE_DATA_FRAME

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "DataFrame":
		mac = super().read_from_buffer(buf)
		mac.duration_id = buf.read_short()
		mac.receiver = MACAddress(buf.read(6))
		mac.transmitter = MACAddress(buf.read(6))
		mac.destination = MACAddress(buf.read(6))
		mac.sequence_control = buf.read_short()
		if mac.flag_from_ds and mac.flag_to_ds:
			mac.source = MACAddress(buf.read(6))
		t = buf.read_remaining()
		mac.data = Buffer.from_bytes(t[:-4], byteorder="little")
		mac.fcs = int.from_bytes(t[-4:], byteorder="little")
		return mac


class Null(DataFrame):
	"""Null frame. Frames with no data used to transmit control
	information."""
	SUBTYPE = FRAME_SUB_TYPE_NULL


class Data(DataFrame):
	"""Data frame. Frames with data.

	Todos:
		* understand is ccmp is always present, not clear.

	Attributes:
		- ccmp_params (int): CCMP parameters.

	"""
	SUBTYPE = FRAME_SUB_TYPE_DATA

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Data":
		mac = super().read_from_buffer(buf)
		mac.ccmp_params = mac.data.read_long()
		return mac


class QoSNull(DataFrame):
	"""QoS Null frame. Frames with no data used to transmit control
	information.

	Attributes:
		- qos_control (int): QoS control.

	"""
	SUBTYPE = FRAME_SUB_TYPE_QOS_NULL

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "QoSNull":
		mac = super().read_from_buffer(buf)
		try:
			mac.qos_control = mac.data.read_short()
		except EndOfBufferError:
			# Some QoS Null packets don't have fcs
			mac.qos_control = mac.fcs
			mac.fcs = None
		return mac


class QoSData(DataFrame):
	"""QoS Data frame. Frames with data.

	Todos:
		* understand is ccmp is always present, not clear.

	Attributes:
		- qos_control (int): QoS control.
		- ccmp_params (int): CCMP parameters.

	"""
	SUBTYPE = FRAME_SUB_TYPE_QOS_DATA

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "QoSData":
		mac = super().read_from_buffer(buf)
		mac.qos_control = mac.data.read_short()
		mac.ccmp_params = mac.data.read_long()
		return mac


frame_class_map = {
	0x00: AssociationRequest,
	0x10: AssociationResponse,
	0x40: ProbeRequest,
	0x50: ProbeResponse,
	0x80: Beacon,
	0x0a: Disassociation,
	0xb0: Authentication,
	0xc0: Deauthentication,
	0xd0: Action,
	0x84: BlockACKRequest,
	0x94: BlockACKResponse,
	0xa4: PowerSavePoll,
	0xb4: RequestToSend,
	0xc4: ClearToSend,
	0xd4: Acknowledgment,
	0xe4: CFEnd,
	0x08: Data,
	0x48: Null,
	0x88: QoSData,
	0xc8: QoSNull,
}


def next_frame_class(buf: Buffer) -> WiFiMAC:
	buf.mark()
	stv = buf.read_byte()
	klass = frame_class_map.get(stv, None)
	buf.restore()
	return klass

