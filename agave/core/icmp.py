"""ICMPv4 protocol."""
from .frame import FrameWithChecksum
from .buffer import Buffer


TYPE_ECHO_REPLY = 0
TYPE_DESTINATION_UNREACHABLE = 3
TYPE_REDIRECT_MESSAGE = 5
TYPE_ECHO_MESSAGE = 8
TYPE_ROUTER_ADVERTISMENT_MESSAGE = 9
TYPE_ROUTER_SOLICITATION_MESSAGE = 10
TYPE_TIME_EXCEEDED = 11

REDIRECT_CODE_NETWORK = 0
REDIRECT_CODE_HOST = 1
REDIRECT_CODE_SERVICE_AND_NETWORK = 2
REDIRECT_CODE_SERVICE_AND_HOST = 3


class ICMP(FrameWithChecksum):
	"""ICMPv4 message, RFC 792.

	Attributes:
		type: ICMP message type
		code: ICMP message code
		checksum: ICMP message checksum
		rest_of_header: ICMP rest of header
		data: data of the message

	"""
	__slots__ = ("type", "code", "checksum", "rest_of_the_header", "data")

	def __init__(self, _type: int, code: int, checksum: int,
		rest_of_the_header: int, data: bytes):
		self.type: int = _type
		self.code: int = code
		self.checksum: int = checksum
		self.rest_of_the_header: int = rest_of_the_header
		self.data: bytes = data

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "ICMPv4":
		"""Parses an ICMPv4 header from a buffer.

		Args:
			buf: the buffer.

		Returns:
			An instance of this class.

		"""
		return cls(
			buf.read_byte(),
			buf.read_byte(),
			buf.read_short(),
			buf.read_int(),
			buf.read_remaining()
		)

	def write_to_buffer(self, buf: Buffer):
		"""Writes this message to a buffer.

		Args:
			buf: the buffer.

		"""
		buf.write_byte(self.type)
		buf.write_byte(self.code)
		buf.write_short(self.checksum)
		buf.write_int(self.rest_of_the_header)
		buf.write(self.data)

	@classmethod
	def echo(cls, data: bytes = b'', identifier: int = 0,
		sequence_number: int = 0
	) -> "ICMPv4":
		return cls(
			TYPE_ECHO_MESSAGE,
			0,
			0,
			sequence_number | (identifier << 16),
			data
		)

	@classmethod
	def reply(cls, data: bytes = b'', identifier = 0, 
		sequence_number = 0
	) -> "ICMPv4":
		return cls(
			TYPE_ECHO_REPLY,
			0,
			0,
			sequence_number | (identifier << 16),
			data
		)
	
	@classmethod
	def redirect(cls, code: int, gway: bytes, data: bytes) -> "ICMPv4":
		"""Builds a redirect message.

		Args:
			code: code.
			gway: the router to use instead.
			data: original message.

		Returns:
			An instance of this class

		"""
		return cls(
			TYPE_REDIRECT_MESSAGE,
			code,
			0,
			gway,
			data
		)

	def compute_checksum(self) -> int:
		"""Compute the checksum for this message.

		Returns:
			The checksum for this message.

		"""
		# Writes header to buffer
		buf = Buffer.from_bytes()
		self.write_to_buffer(buf)
		words = 4 + int(len(self.data) / 2)
		# Pads
		if len(self.data) % 2 == 1:
			buf.write_byte(0)
			words +=1
		buf.rewind()
		# Compute
		return self.compute_checksum_from_buffer(buf, words)

	def __str__(self):
		return "ICMP {} {}".format(self.type, self.code)


class ICMPv4(ICMP):
	pass

