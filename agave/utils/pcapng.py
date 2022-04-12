"""PCAP Next Generation format.
Utilities to parse/dump packets from/to file.

Note:
	Specs:
		https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html
	Link Types:
		https://www.tcpdump.org/linktypes.html

"""
from agave.core.frame import Frame
from agave.core.buffer import Buffer, EndOfBufferError


BLOCK_TYPE_SECTION_HEADER = 0x0A0D0D0A
BLOCK_TYPE_INTERFACE_DESCRIPTION = 1
BLOCK_TYPE_SIMPLE_PACKET_BLOCK = 3


BYTE_ORDER_MAGIC = 0x1A2B3C4D


LINKTYPE_ETHERNET = 1					# IEEE 802.3
LINKTYPE_RAW = 101						# IPv4 or IPv6 header
LINKTYPE_IEEE802_11 = 105				# IEEE 802.11
LINKTYPE_IEEE802_11_RADIOTAP = 127		# Radio Tap followed by IEEE 802.11


LINKTYPE_TO_STR = {
	LINKTYPE_ETHERNET: "IEEE 802.3 Ethernet",
	LINKTYPE_RAW: "IP raw",
	LINKTYPE_IEEE802_11: "IEEE 802.11 WiFi",
	LINKTYPE_IEEE802_11_RADIOTAP: "Radio Tap + IEEE 802.11",
}


class Block(Frame):
	"""General block structure.

	Attributes:
		type: block type.
		length: total block length.
		body: body of the block.

	"""
	__slots__ = ("type", "length", "body")

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Block":
		x = cls()
		x.type = buf.read_int()
		x.length = buf.read_int()
		x.body = buf.read(x.length - 12)
		assert buf.read_int() == x.length
		return x

	def write_to_buffer(self, buf: Buffer):
		buf.write_int(self.type)
		buf.write_int(self.length)
		buf.write_int(self.body)
		buf.write_int(self.length)

	def __str__(self):
		return "Block {}".format(self.type)


class SectionHeader(Block):
	"""Interface Description block.

	Attributes:
		type: block type.
		length: block length.
		byte_order_magic: filed used to check endianness.
		major: major version, max value 1.
		minor: minor version, min value 0.
		section_length: total length of the section, excluding this block.
		options: options.

	"""
	__slots__ = ("byte_order_magic", "major", "minor", "section_length", "options")

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		x = cls()
		# General
		x.type = buf.read_int()
		if x.type != BLOCK_TYPE_SECTION_HEADER:
			raise ValueError("Incorrect block type value {}".format(x.type))
		x.length = buf.read_int()
		# Specific
		x.byte_order_magic = buf.read_int()
		if x.byte_order_magic != BYTE_ORDER_MAGIC:
			raise ValueError("Incorrect endianness for this buffer.")
		x.major = buf.read_short()
		x.minor = buf.read_short()
		x.section_length = buf.read_long()
		x.options = buf.read(x.length - 28)
		# General
		assert buf.read_int() == x.length
		return x

	def write_to_buffer(self, buf: Buffer):
		# General
		buf.write_int(self.type)
		buf.write_int(self.length)
		# Specific
		buf.write_int(self.byte_order_magic)
		buf.write_short(self.major)
		buf.write_short(self.minor)
		buf.write_long(self.section_length)
		buf.write(self.options)
		# General
		buf.write_int(self.length)

	@classmethod
	def build(cls, options: bytes = b'', section_length: int = 0xffffffffffffffff) -> "SectionHeader":
		x = cls()
		x.type = BLOCK_TYPE_SECTION_HEADER
		x.length = 28 + len(options)
		x.byte_order_magic = BYTE_ORDER_MAGIC
		x.major = 1
		x.minor = 0
		x.section_length = section_length
		x.options = options
		return x

	def __str__(self):
		return "SectionHeader {}.{}".format(self.major, self.minor)


class InterfaceDescription(Block):
	"""Interface Description block.

	Attributes:
		type: block type.
		length: block length.
		linktype: linktype.
		snaplen: max number of bytes captured for each packet.
		options: options.

	"""
	__slots__ = ("linktype", "reserved", "snaplen", "options")

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		x = cls()
		# General
		x.type = buf.read_int()
		if x.type != BLOCK_TYPE_INTERFACE_DESCRIPTION:
			raise ValueError("Incorrect block type value {}".format(x.type))
		x.length = buf.read_int()
		# Specific
		x.linktype = buf.read_short()
		x.reserved = buf.read_short()
		x.snaplen = buf.read_int()
		x.options = buf.read(x.length - 20)
		# General
		assert buf.read_int() == x.length
		return x

	def write_to_buffer(self, buf: Buffer):
		# General
		buf.write_int(self.type)
		buf.write_int(self.length)
		# Specific
		buf.write_int(self.linktype)
		buf.write_short(self.reserved)
		buf.write_short(self.snaplen)
		buf.write(self.options)
		# General
		buf.write_int(self.length)

	@classmethod
	def build(cls, linktype: int, snaplen: int, options: bytes = b'') -> "SectionHeader":
		x = cls()
		x.type = BLOCK_TYPE_INTERFACE_DESCRIPTION
		x.length = 20 + len(options)
		# Specific
		x.linktype = linktype
		x.reserved = 0
		x.snaplen = snaplen
		x.options = options
		return x

	def __str__(self):
		return "InterfaceDescription - {}".format(LINKTYPE_TO_STR.get(self.linktype, self.linktype))


class SimplePacket(Block):
	"""Simple Packet block.

	Attributes:
		type: block type.
		length: block length.
		original_packet_length: packet size.
		data: packet.

	"""
	__slots__ = ("original_packet_length", "data", "pad")

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		x = cls()
		# General
		x.type = buf.read_int()
		if x.type != BLOCK_TYPE_SIMPLE_PACKET_BLOCK:
			raise ValueError("Incorrect block type value {}".format(x.type))
		x.length = buf.read_int()
		# Specific
		x.original_packet_length = buf.read_int()
		x.data = buf.read(x.original_packet_length)
		x.pad = buf.read(x.length - x.original_packet_length - 12)
		# General
		assert buf.read_int() == x.length
		return x

	def write_to_buffer(self, buf: Buffer):
		# General
		buf.write_int(self.type)
		buf.write_int(self.length)
		# Specific
		buf.write_int(self.original_packet_length)
		buf.write(self.data)
		buf.write(self.pad)
		# General
		buf.write_int(self.length)

	@classmethod
	def build(cls, data: bytes) -> "SectionHeader":
		x = cls()
		x.type = BLOCK_TYPE_SIMPLE_PACKET_BLOCK
		x.original_packet_length = len(data)
		x.data = data
		t = len(data) % 4
		x.pad = b'' if t == 0 else bytes(4 - t)
		x.length = 16 + len(data) + len(x.pad)
		return x

	def __str__(self):
		return "SimplePacket - Size {}".format(len(self.original_packet_length))


BLOCK_MAP = {
	BLOCK_TYPE_SECTION_HEADER: SectionHeader,
	BLOCK_TYPE_INTERFACE_DESCRIPTION: InterfaceDescription,
	BLOCK_TYPE_SIMPLE_PACKET_BLOCK: SimplePacket
}


def get_next_block_class(buf: Buffer):
	buf.mark()
	k = BLOCK_MAP.get(buf.read_int(), Block)
	buf.restore()
	return k


class SimpleDumper:
	"""Basic class to dump packet to pcapng file. Useful for debug."""
	__slots__ = ("buf")

	def __init__(self, buf: Buffer):
		self.buf = buf

	def start_section(self, linktype: int, snaplen: int):
		SectionHeader.build().write_to_buffer(self.buf)
		InterfaceDescription.build(linktype=linktype, snaplen=snaplen).write_to_buffer(self.buf)

	def dump(self, packet: bytes):
		SimplePacket.build(packet).write_to_buffer(self.buf)

