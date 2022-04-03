from .frame import Frame, FrameWithChecksum
from .buffer import Buffer
from ipaddress import ip_address, IPv4Address, IPv6Address


PROTO_ICMP = 0x01
PROTO_TCP = 0x06
PROTO_UDP = 0x11
PROTO_ICMPv6 = 0x3A

PROTO_IPv6_HOPOPT = 0x00
PROTO_IPv6_ROUTE = 0x2B
PROTO_IPv6_FRAG = 0x2C
PROTO_IPv6_NoNXT = 0x3B
PROTO_IPv6_OPTS = 0x3C

IPv6_EXTENSION = [
	PROTO_IPv6_ROUTE,
	PROTO_IPv6_FRAG,
	PROTO_IPv6_NoNXT,
	PROTO_IPv6_OPTS
]


class IPv4(FrameWithChecksum):

	__slots__ = (
		"version", "ihl", "dscp", "ecn", "total_length", "identification",
		"flags", "fragment_offset", "ttl", "protocol", "checksum", "source",
		"destination", "options"
	)

	def __init__(self, ihl, dscp, ecn, total_length, identification, flags,
			fragment_offset, ttl, protocol, checksum, source, destination, options):
		self.version = 4
		self.ihl = ihl
		self.dscp = dscp
		self.ecn = ecn
		self.total_length = total_length
		self.identification = identification
		self.flags = flags
		self.fragment_offset = fragment_offset
		self.ttl = ttl
		self.protocol = protocol
		self.checksum = checksum
		self.source = source
		self.destination = destination
		self.options = options

	@classmethod
	def read_from_buffer(cls, buf):
		
		v_ihl = buf.read_byte()
		# protocol version
		version = v_ihl >> 4
		# Internet header length (number of 32 bits words in the header)
		ihl = v_ihl & 0x0F

		dscp_ecn = buf.read_byte()
		# Differentiated service code point (originally ToS)
		dscp = dscp_ecn >> 2
		# Explicit congestion notification
		ecn = dscp_ecn & 0x03

		total_length = buf.read_short()
		identification = buf.read_short()

		flags_f_offset = buf.read_short()
		flags = flags_f_offset >> 13
		fragment_offset = flags_f_offset & 0x1FFF
	
		# Time To Live - hop limit in IPv6
		ttl = buf.read_byte()
		# Protocol - next header in IPv6
		protocol = buf.read_byte()

		checksum = buf.read_short()

		# addresses
		source = buf.read(4)
		destination = buf.read(4)

		options = buf.read(ihl * 4 - 20)

		return cls(ihl, dscp, ecn, total_length, identification, flags,
			fragment_offset, ttl, protocol, checksum, source, destination, options)

	def write_to_buffer(self, buf):
		buf.write_byte((self.version << 4) + self.ihl)
		buf.write_byte((self.dscp << 2) + self.ecn)
		buf.write_short(self.total_length)
		buf.write_short(self.identification)
		buf.write_short((self.flags << 13) + self.fragment_offset)
		buf.write_byte(self.ttl)
		buf.write_byte(self.protocol)
		buf.write_short(self.checksum)
		buf.write(self.source)
		buf.write(self.destination)
		buf.write(self.options)

	def compute_checksum(self):
		# Writes header to buffer
		buf = Buffer.from_bytes()
		self.write_to_buffer(buf)
		buf.rewind()
		# Computes the checksum
		words = self.ihl * 2
		return self.compute_checksum_from_buffer(buf, words)

	def __str__(self):
		return "({}) {} -> {}".format(
			self.protocol,
			str(ip_address(self.source)),
			str(ip_address(self.destination))
		)

	@classmethod
	def create_message(
		cls,
		destination: IPv4Address,
		source: IPv4Address,
		payload: bytes,
		proto: int
	) -> bytes:
		buf = Buffer.from_bytes()
		ip_frame = cls(
			ihl=5, 
			dscp=0,
			ecn=0,
			total_length=(20 + len(payload)),
			identification=0,
			flags=2, 								# don't fragment
			fragment_offset=0,
			ttl=64,
			protocol=proto,
			checksum=0,
			source=source.packed,
			destination=destination.packed,
			options=b''
		)
		ip_frame.set_checksum()
		ip_frame.write_to_buffer(buf)
		buf.write(payload)
		return bytes(buf)


class IPv6(Frame):
	"""IPv6 message, RFC 8200.

	Attributes:
		version: IPv6 version
		traffic_class: IPv6 traffic class.
		flow_label: IPv6 flow label.
		payload_length: IPv6 payload length.
		next_header: IPv6 next header.
		hop_limit: IPv6 hop limit.
		source: IPv6 source.
		destination: IPv6 destination.
		extensions: unparsed extension.
	
	Todo:
		* handle extension headers.

	"""
	__slots__ = (
		"traffic_class", "flow_label", "payload_length", "next_header",
		"hop_limit", "source", "destination", "extensions", "version"
	)

	def __init__(
		self,
		traffic_class: int,
		flow_label: int,
		payload_length: int,
		next_header: int,
		hop_limit: int,
		source: IPv6Address,
		destination: IPv6Address,
		extensions: bytes = None
	):
		self.version: int = 6
		self.traffic_class: int = traffic_class
		self.flow_label: int = flow_label
		self.payload_length: int = payload_length
		self.next_header: int = next_header
		self.hop_limit: int = hop_limit
		self.source: IPv6Address = source
		self.destination: IPv6Address = destination
		self.extensions: bytes = b''

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "IPv6":
		"""Parses an IPv6 header from a buffer.

		Args:
			buf: the buffer.

		Returns:
			An instance of this class.

		Todo:
			* parse extension headers

		"""
		temp = buf.read_int()
		traffic_class = (temp & 0x0ff00000) >> 20
		flow_label = temp & 0x000fffff
		payload_length = buf.read_short()
		next_header = buf.read_byte()
		hop_limit = buf.read_byte()
		source = IPv6Address(buf.read(16))
		destination = IPv6Address(buf.read(16))
		return cls(
			traffic_class,
			flow_label,
			payload_length,
			next_header,
			hop_limit,
			source,
			destination
		)

	def write_to_buffer(self, buf: Buffer):
		"""Writes this message headers on a buffer.

		Args:
			buf: the buffer.

		"""
		buf.write_int(0x60000000 | (self.traffic_class << 20) | self.flow_label)
		buf.write_short(self.payload_length)
		buf.write_byte(self.next_header)
		buf.write_byte(self.hop_limit)
		buf.write(self.source.packed)
		buf.write(self.destination.packed)
		buf.write(self.extensions)

	def __str__(self):
		return "({}) {} -> {}".format(
			self.next_header,
			self.source,
			self.destination
		)

	def get_pseudo_header(self) -> bytes:
		"""Builds the pseudo header for this IPv6 message.

		Returns:
			The pseudo header.

		Todo:
			* replace next_header with upper layer protocol, or
				this will break with extensions.
			* replace payload_length with upper protocol packet
				size, or this will break with extensions.

		"""
		return self.build_pseudo_header(
			self.source,
			self.destination,
			self.payload_length,
			self.next_header
		)

	def build_pseudo_header(
		self,
		source: IPv6Address,
		destination: IPv6Address,
		packet_length: int,
		next_header: int
	) -> bytes:
		"""Builds the pseudo header necessary to upper protocols
		for checksum calculation.

		Args:
			source: source address.
			destination: destination address.
			packet_length: upper layer header and data size.
			next_header: upper layer protocol.

		"""
		return (
			source.packed + 
			destination.packed + 
			packet_length.to_bytes(4, byteorder="big") +
			b'\x00\x00\x00' +
			next_header.to_bytes(1, byteorder="big")
		)

