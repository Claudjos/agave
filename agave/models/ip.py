"""IP protocol."""
from .frame import Frame, FrameWithChecksum
from .buffer import Buffer
from typing import Union
from ipaddress import (
	ip_address, IPv4Address, IPv6Address, IPv4Network, IPv6Network
)


IP_ADDRESS = Union[IPv4Address, IPv6Address]
IP_NETWORK = Union[IPv4Network, IPv6Network]

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

IPV4_ALL_NODES_MULTICAST = "224.0.0.1"
IPV4_ALL_ROUTERS_MULTICAST = "224.0.0.2"

IPV6_ALL_NODES_MULTICAST_INTERFACE_LOCAL = "FF01:0:0:0:0:0:0:1"
IPV6_ALL_NODES_MULTICAST_LINK_LOCAL = "FF02:0:0:0:0:0:0:1"
IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL = "FF01:0:0:0:0:0:0:2"
IPV6_ALL_ROUTERS_MULTICAST_LINK_LOCAL = "FF02:0:0:0:0:0:0:2"
IPV6_ALL_ROUTERS_MULTICAST_SITE_LOCAL = "FF05:0:0:0:0:0:0:2"


class IPHeader:
	"""Common properties for IP headers.

	Attributes:
		source (IP_ADDRESS): source address.
		destination (IP_ADDRESS): destination address.

	"""
	def get_upper_layer_protocol(self) -> int:
		"""Returns payload protocol."""
		raise NotImplementedError()

	def get_upper_layer_length(self) -> int:
		"""Returns payload length."""
		raise NotImplementedError()

	def get_pseudo_header(self) -> bytes:
		"""Returns a pseudo header for checksum computation of transport
		layer protocols."""
		return self.build_pseudo_header(self.source, self.destination,
			self.get_upper_layer_protocol(), self.get_upper_layer_length())

	@classmethod
	def build_pseudo_header(cls, source: IP_ADDRESS, destination: IP_ADDRESS,
		protocol: int, payload_length: int) -> bytes:
		"""Returns a pseudo header for checksum computation of transport
		layer protocols."""
		raise NotImplementedError()

	def __str__(self):
		return "({}) {} -> {}".format(
			self.get_upper_layer_protocol(),
			self.source,
			self.destination
		)


class IPv4(IPHeader, FrameWithChecksum):
	"""IPv4 header.

	Attributes:
		version: IPv4 version.
		ihl: IPv4 Intern Header Length.
		dscp: IPv4 Differentiated Service Code Point (originally ToS).
		ecn: IPv4 Explicit Congestion Notification.
		total_length: IPv4 total length.
		identification: IPv4 identification.
		flags: IPv4 flags.
		fragment_offset: IPv4 fragment offset.
		ttl: IPv4 Time To Live.
		protocol: IPv4 protocol.
		checksum: IPv4 checksum.
		source: IPv4 source address.
		destination: IPv4 destination address.
		options: IPv4 options.

	"""
	__slots__ = (
		"version", "ihl", "dscp", "ecn", "total_length", "identification",
		"flags", "fragment_offset", "ttl", "protocol", "source", "destination",
		"options"
	)

	def __init__(self, ihl: int, dscp: int, ecn: int, total_length: int,
		identification: int, flags: int, fragment_offset: int, ttl: int,
		protocol: int, checksum: int, source: IPv4Address, 
		destination: IPv4Address, options: bytes
	):
		self.version: int = 4
		self.ihl: int = ihl
		self.dscp: int = dscp
		self.ecn: int = ecn
		self.total_length: int = total_length
		self.identification: int = identification
		self.flags: int = flags
		self.fragment_offset: int = fragment_offset
		self.ttl: int = ttl
		self.protocol: int = protocol
		self.checksum: int = checksum
		self.source: IPv4Address = source
		self.destination: IPv4Address = destination
		self.options: bytes = options

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "IPv4":
		"""Parses an IPv4 header from a buffer.

		Args:
			buf: the buffer.

		Returns:
			An instance of this class.

		"""
		v_ihl = buf.read_byte()
		version = v_ihl >> 4
		ihl = v_ihl & 0x0F
		dscp_ecn = buf.read_byte()
		dscp = dscp_ecn >> 2
		ecn = dscp_ecn & 0x03
		total_length = buf.read_short()
		identification = buf.read_short()
		flags_f_offset = buf.read_short()
		flags = flags_f_offset >> 13
		fragment_offset = flags_f_offset & 0x1FFF
		ttl = buf.read_byte()
		protocol = buf.read_byte()
		checksum = buf.read_short()
		source = IPv4Address(buf.read(4))
		destination = IPv4Address(buf.read(4))
		options = buf.read(ihl * 4 - 20)
		return cls(ihl, dscp, ecn, total_length, identification, flags,
			fragment_offset, ttl, protocol, checksum, source, destination, options)

	def write_to_buffer(self, buf: Buffer):
		"""Writes this message headers on a buffer.

		Args:
			buf: the buffer.

		"""
		buf.write_byte((self.version << 4) + self.ihl)
		buf.write_byte((self.dscp << 2) + self.ecn)
		buf.write_short(self.total_length)
		buf.write_short(self.identification)
		buf.write_short((self.flags << 13) + self.fragment_offset)
		buf.write_byte(self.ttl)
		buf.write_byte(self.protocol)
		buf.write_short(self.checksum)
		buf.write(self.source.packed)
		buf.write(self.destination.packed)
		buf.write(self.options)

	@classmethod
	def create_message(
		cls,
		destination: IPv4Address,
		source: IPv4Address,
		payload: bytes,
		proto: int,
		ttl: int = 64
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
			ttl=ttl,
			protocol=proto,
			checksum=0,
			source=source,
			destination=destination,
			options=b''
		)
		ip_frame.set_checksum()
		ip_frame.write_to_buffer(buf)
		buf.write(payload)
		return bytes(buf)

	@classmethod
	def build_pseudo_header(
		cls,
		source: IPv4Address,
		destination: IPv4Address,
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
			b'\x00' +
			next_header.to_bytes(1, byteorder="big") +
			packet_length.to_bytes(2, byteorder="big")
		)

	def get_upper_layer_protocol(self) -> int:
		return self.protocol

	def get_upper_layer_length(self) -> int:
		return self.total_length - self.ihl * 4

	@property
	def hop_limit(self):
		return self.ttl


class IPv6(IPHeader, Frame):
	"""IPv6 header, RFC 8200.

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
		extensions: bytes = b''
	):
		self.version: int = 6
		self.traffic_class: int = traffic_class
		self.flow_label: int = flow_label
		self.payload_length: int = payload_length
		self.next_header: int = next_header
		self.hop_limit: int = hop_limit
		self.source: IPv6Address = source
		self.destination: IPv6Address = destination
		self.extensions: bytes = extensions

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

	def get_upper_layer_protocol(self) -> int:
		"""Breaks with extensions."""
		return self.next_header

	def get_upper_layer_length(self) -> int:
		"""Breaks with extensions."""
		return self.payload_length

	@classmethod
	def build_pseudo_header(
		cls,
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


def read_from_buffer(buf: Buffer) -> IPHeader:
	"""Reads an IP header from buffer.

	Returns:
		The IP header.

	Raises:
		ValueError, if the buffer doesn't contain an IP header version
			4 or 6.
	"""
	buf.mark()
	version = buf.read_byte() >> 4 & 0x0f
	buf.restore()
	if version == 4:
		return IPv4.read_from_buffer(buf)
	if version == 6:
		return IPv6.read_from_buffer(buf)
	raise ValueError(f"Buffer contained unsupported protocol header version {version}")

