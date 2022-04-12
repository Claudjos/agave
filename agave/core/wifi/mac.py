import struct
from agave.core.frame import Frame
from agave.core.buffer import Buffer, EndOfBufferError
from agave.core.ethernet import MACAddress
from .tags import TaggedParameter


_all_map = {
	0x00: ("Management Frame", {
		0: "Association request",
		1: "Association response",
		2: "Reassociation request",
		3: "Reassociation response",
		4: "Probe request",
		5: "Probe response",
		6: "Timing advertisement",
		7: "Reserved",
		8: "Beacon",
		10: "Disassociation",
		11: "Authentication",
		12: "Deauthentication",
		16: "Action",
	}),
	0x01: ("Control Frame", {
		8: "Block ACK Req",
		9: "Block ACK",
		11: "Request-To-Send",
		12: "Clear-To-Send",
		13: "Acknowledgment"
	}),
	0x02: ("Data Frame", {
		0: "Data",
		4: "Null Function (No data)",
		8: "QoS Data",
		12: "QoS Null Function"
	})

}


class MAC_802_11(Frame):

	def is_probe_response(self) -> bool:
		return self.subtype == 5 and self.type == 0

	def is_become_frame(self) -> bool:
		return self.subtype == 8 and self.type == 0

	@classmethod
	def read_from_buffer(cls, buf):
		mac = cls()
		mac._frame_control_fields = buf.read_byte()
		mac._flags = buf.read_byte()
		mac.duration_id = buf.read_short()
		
		mac.receiver = None
		mac.destination = None
		mac.source = None
		mac.transmitter = None
		mac.BSSID = None

		# if data frame or management frame
		if mac.type == 2 or mac.type == 0:

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

		if mac.type == 1:
			# parse differently
			mac.receiver = MACAddress(buf.read(6))
			mac.sequence_control = buf.read_short()

		return mac

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


class WirelessManagement(Frame):

	@classmethod
	def read_from_buffer(cls, buf, with_fixed=True):
		frame = cls()
		frame.tags = {}
		if with_fixed:
			frame.timestamp = int.from_bytes(buf.read(8), byteorder="little")
			frame.beacon_interval = buf.read(2)
			frame.capabilities_information = buf.read(2)
		# parse tags
		frame.tags = TaggedParameter.parse_all(buf)
		return frame
