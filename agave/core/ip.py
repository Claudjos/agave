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
	"""IPv6 RFC 8200
	
	Todo:
		* handle extension headers.

	"""
	def __init__(
		self,
		traffic_class: int,
		flow_label: int,
		payload_length: int,
		next_header: int,
		hop_limit: int,
		source: IPv6Address,
		destination: IPv6Address,
		extensions = None
	):
		self.version = 6
		self.traffic_class = traffic_class
		self.flow_label = flow_label
		self.payload_length = payload_length
		self.next_header = next_header
		self.hop_limit = hop_limit
		self.source = source
		self.destination = destination
		self.extensions = b''

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "IPv6":
		"""Parses an IPv6 header from a buffer.

		Args:
			buf: buffer to parse from.

		Returns:
			IPv6 header data.

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
		"""Writes the IPv6 header on a buffer.

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
		"""
		Todo:
			* next_header refers to the upper protocol, thus
				this is gonna break with extensions.
			* payload_length refers to the upper protocol, thus
				this is gonna break with extensions.
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
		payload_length: int,
		next_header: int
	) -> bytes:
		return (
			source.packed + 
			destination.packed + 
			payload_length.to_bytes(4, byteorder="big") +
			b'\x00\x00\x00' +
			next_header.to_bytes(1, byteorder="big")
		)

