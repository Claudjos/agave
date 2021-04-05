from .core import FrameWithChecksum, Buffer
from ipaddress import ip_address


PROTO_ICMP = 0x01
PROTO_TCP = 0x06
PROTO_UDP = 0x11


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
