"""LLC Logical Link Control."""
from .frame import Frame
from .buffer import Buffer


LSAP_SNAP = 0xaa 	# SNAP Extension
LSAP_STP = 0x42 	# IEEE 802.1 Bridge Spanning Tree Protocol


class LLC(Frame):
	"""802.2 LLC Header with SNAP extension SubNetwork Access Protocol.

	Attributes:
		dsap (int): Destination Service Access Point.
		ssap (int): Source Service Access Point.
		control (int): control field.
		sequence (int): sequence field.
		oui (bytes): SNAP extension, OUI Organizational Unique Identifier.
		next_header (int): SNAP extension, protocol ID.

	"""
	__slots__ = ("dsap", "ssap", "control", "sequence", "oui", "next_header")

	BYTEORDER = "big"

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "LLC":
		x = LLC()
		x.dsap = buf.read_byte()
		x.ssap = buf.read_byte()
		x.control = buf.read_byte()
		if x.control & 0x03 != 0x03:
			x.sequence = buf.read_byte()
		else:
			x.sequence = None
		if x.dsap == LSAP_SNAP:
			x.oui = buf.read(3)
			x.next_header = buf.read_short()
		else:
			x.oui = x.next_header = None
		return x

	def write_to_buffer(self, buf: Buffer):
		buf.write_byte(self.dsap)
		buf.write_byte(self.ssap)
		buf.write_byte(self.control)
		if self.sequence is not None:
			buf.write_byte(self.sequence)
		if self.oui is not None and self.next_header is not None:
			buf.write(self.oui)
			buf.write_short(self.next_header)

	def is_multicast(self):
		"""Checks the I/G bit (Individual/Group)."""
		return self.dsap & 0x01 == 0x01

	def is_unicast(self) -> bool:
		return not self.is_multicast()

	def is_response(self) -> bool:
		"""Checks the C/R bit (Command/Response)."""
		return self.ssap & 0x01 == 0x01

	def is_command(self) -> bool:
		return not self.is_response()

	@classmethod
	def build_snap(cls, next_header: int) -> "LLC":
		x = cls()
		x.ssap = x.dsap = LSAP_SNAP
		x.control = 0x03
		x.sequence = None
		x.oui = b'\x00\x00\x00'
		x.next_header = next_header
		return x

