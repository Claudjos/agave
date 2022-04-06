"""ICMPv6 protocol."""
from .frame import FrameWithChecksum
from .buffer import Buffer


TYPE_ECHO_REQUEST = 128
TYPE_ECHO_REPLY = 129

# NDP Message types
TYPE_ROUTER_SOLICITATION = 133
TYPE_ROUTER_ADVERTISEMENT = 134
TYPE_NEIGHBOR_SOLICITATION = 135
TYPE_NEIGHBOR_ADVERTISEMENT = 136
TYPE_REDIRECT_MESSAGE = 137


class ICMPv6(FrameWithChecksum):
	"""ICMPv6 message, RFC 4443.

	Attributes:
		type: ICMP message type,
		code: ICMP message code,
		checksum: ICMP message checksum,
		body: next 4 bytes of ICMP message,
		payload: rest of the data.
		_pseudo_header: IPv6 pseudo header for checksum computation.

	"""
	__slots__ = ("type", "code", "checksum", "body", "_pseudo_header")

	def __init__(
		self,
		_type: int,
		code: int,
		checksum: int,
		body: bytes
	):
		self.type: int = _type
		self.code: int = code
		self.checksum: int = checksum
		self.body: bytes = body
		self._pseudo_header : bytes = b''

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ICMPv6":
		"""Parses an ICMPv6 message from a Buffer.

		Args:
			buf: the buffer.

		Returns:
			An instance of this class.

		"""
		return cls(
			buf.read_byte(),
			buf.read_byte(),
			buf.read_short(),
			buf.read_remaining()
		)

	def write_to_buffer(self, buf: Buffer):
		"""Writes this ICMPv6 message to a buffer.

		Args:
			buf: the buffer.

		"""
		buf.write_byte(self.type)
		buf.write_byte(self.code)
		buf.write_short(self.checksum)
		buf.write(self.body)

	def set_pseudo_header(self, header: bytes):
		"""Sets the pseudo header to use when
		calculating checksum.
		
		Args:
			header: the pseudo header.

		"""
		self._pseudo_header = header

	def compute_checksum(self) -> int:
		"""Compute the checksum for this message.

		Returns:
			The checksum for this message.

		"""
		# Writes header to buffer
		buf = Buffer.from_bytes()
		buf.write(self._pseudo_header)
		self.write_to_buffer(buf)
		words = 2 + int(len(self.body) / 2) + int(len(self._pseudo_header) / 2)
		# Pads (?)
		if len(self.body) % 2 == 1:
			buf.write_byte(0)
			words +=1
		buf.rewind()
		# Compute
		t = self.compute_checksum_from_buffer(buf, words)
		return t

