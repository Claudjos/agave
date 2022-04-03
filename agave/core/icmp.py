"""
ICMP definition @ RFC 792
"""
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

	def __init__(self, _type: int, code: int, checksum: int, rest_of_the_header: int,
			data: bytes):
		self.type = _type
		self.code = code
		self.checksum = checksum
		self.rest_of_the_header = rest_of_the_header
		self.data = data

	@classmethod
	def read_from_buffer(self, buf):
		return ICMP(
			buf.read_byte(),
			buf.read_byte(),
			buf.read_short(),
			buf.read_int(),
			buf.read_remaining()
		)

	def write_to_buffer(self, buf):
		buf.write_byte(self.type)
		buf.write_byte(self.code)
		buf.write_short(self.checksum)
		buf.write_int(self.rest_of_the_header)
		buf.write(self.data)

	@classmethod
	def echo(cls, data = b'', identifier = 0, sequence_number = 0):
		return cls(
			TYPE_ECHO_MESSAGE,
			0,
			0,
			sequence_number | (identifier << 16),
			data
		)

	@classmethod
	def reply(cls, data = b'', identifier = 0, sequence_number = 0):
		return cls(
			TYPE_ECHO_REPLY,
			0,
			0,
			sequence_number | (identifier << 16),
			data
		)
	
	@classmethod
	def redirect(cls, code: int, gway: bytes, data: bytes):
		"""
		PARAMS
			code: code.
			gway: the router to use instead.
			data: original message.
		"""
		return cls(
			TYPE_REDIRECT_MESSAGE,
			code,
			0,
			gway,
			data
		)

	def compute_checksum(self):
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

