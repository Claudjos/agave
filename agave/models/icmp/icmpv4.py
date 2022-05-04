"""ICMPv4 protocol."""
from .frame import _FrameWithChecksum, Frame
from .buffer import Buffer
from .ethernet import Ethernet
from .ip import IPv4
from typing import List


TYPE_ECHO_REPLY = 0
TYPE_DESTINATION_UNREACHABLE = 3
TYPE_REDIRECT_MESSAGE = 5
TYPE_ECHO_MESSAGE = 8
TYPE_ROUTER_ADVERTISMENT_MESSAGE = 9
TYPE_ROUTER_SOLICITATION_MESSAGE = 10
TYPE_TIME_EXCEEDED = 11
TYPE_ADDRESS_MASK_REQUEST = 17
TYPE_ADDRESS_MASK_REPLY = 18

REDIRECT_CODE_NETWORK = 0
REDIRECT_CODE_HOST = 1
REDIRECT_CODE_SERVICE_AND_NETWORK = 2
REDIRECT_CODE_SERVICE_AND_HOST = 3


class ICMPv4(_FrameWithChecksum):
	"""ICMPv4 message, RFC 792.

	Attributes:
		type: ICMPv4 message type
		code: ICMPv4 message code
		checksum: ICMPv4 message checksum
		rest_of_header: ICMPv4 rest of header
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
			An instance of this class..

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
			An instance of this class.

		"""
		return cls(
			TYPE_REDIRECT_MESSAGE,
			code,
			0,
			gway,
			data
		)

	@classmethod
	def address_mask_request(cls, sequence_number: int = 0, identifier: int = 0) -> "ICMPv4":
		"""Builds an address mask request.

		Returns:
			An instance of this class.

		"""
		return cls(
			TYPE_ADDRESS_MASK_REQUEST,
			0,
			0,
			sequence_number | (identifier << 16),
			b'\x00\x00\x00\x00'
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

	@classmethod
	def parse(cls, data: bytes, network: bool = True, data_link: bool = False) -> List[Frame]:
		"""Parses ICMPv4 message, including sub layers, from bytes.

		Args:
			data: bytes received.
			network: True if data includes IPv4 header.
			data_link: True if data includes EthernetII header.
		
		Returns:
			A list with all the frames parsed.

		"""
		frames = []
		buf = Buffer.from_bytes(data)
		if data_link:
			frames.append(Ethernet.read_from_buffer(buf))
		if network:
			frames.append(IPv4.read_from_buffer(buf))
		frames.append(cls.read_from_buffer(buf))
		return frames
