"""PCAP Next Generation. 
Models to work with PCAP Next Generation data.

Todo:
	* parse options.

Note:
	Specs:
		https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html
	Link Types:
		https://www.tcpdump.org/linktypes.html

"""
from typing import Tuple, Any, List
from sys import byteorder
from agave.core.frame import Frame
from agave.core.buffer import Buffer, EndOfBufferError
from agave.core.ethernet import MACAddress
from ipaddress import IPv4Address, IPv6Address, IPv6Network


BLOCK_TYPE_SECTION_HEADER = 0x0A0D0D0A
BLOCK_TYPE_INTERFACE_DESCRIPTION = 1
BLOCK_TYPE_SIMPLE_PACKET_BLOCK = 3
BLOCK_TYPE_ENHANCED_PACKET_BLOCK = 6


OPTION_TYPE_ENDOFOPT = 0
OPTION_TYPE_COMMENT = 1
OPTION_TYPE_IF_NAME = 2
OPTION_TYPE_IF_DESCRIPTION = 3
OPTION_TYPE_IF_IPV4ADDR	= 4
OPTION_TYPE_IF_IPV6ADDR	= 5
OPTION_TYPE_IF_MACADDR = 6


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


class EndiannessError(Exception):
	pass


class Option(Frame):
	"""Block option.

	Attributes:
		code: option code.
		length: value size (without pad).
		_value: option value.

	"""
	__slots__ = ("code", "length", "_value", "pad")

	OPT_CODE = None
	BYTEORDER = byteorder

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "Option":
		x = cls()
		x.code = buf.read_short()
		x.length = buf.read_short()
		x._value = buf.read(x.length)
		x.pad = buf.read(count_pad_32(x.length))
		return x

	def write_to_buffer(self, buf: Buffer):
		buf.write_short(self.code)
		buf.write_short(self.length)
		buf.write(self._value)
		buf.write(self.pad)

	@classmethod
	def build(cls, value: Any = b'', code: int = None) -> "Option":
		x = cls()
		x.code = code if cls.OPT_CODE is None else cls.OPT_CODE
		x.value = value
		return x

	def set_value(self, value: bytes):
		self.length = len(value)
		self._value = value
		self.pad = bytes(count_pad_32(self.length))

	@property
	def value(self) -> bytes:
		return self._value

	@value.setter
	def value(self, x: bytes):
		self.set_value(x)

	@classmethod
	def decode(self, data: bytes, endianness: str) -> List["Option"]:
		"""Decode bytes into options.

		Args:
			data: bytes.
			endianness: the byte order of the option; depends on the
				encoding machine byteorder.

		Returns:
			A list of option.

		"""
		output = []
		buf = Buffer.from_bytes(data, byteorder=endianness)
		try:
			while True:
				x = get_next_option_class(buf).read_from_buffer(buf)
				if isinstance(x, EndOfOptions):
					break
				output.append(x)
		except EndOfBufferError:
			# Maybe log a debug message
			pass
		finally:
			return output

	@classmethod
	def encode(self, opts: List["Option"], endianness: str = None) -> bytes:
		"""Encode options into bytes.

		Args:
			opts: list of option.
			endianness: the byte order; default to the machine one.

		Returns:
			The options as bytes, completed with the EndOfOptionss.

		"""
		if opts is None:
			return b''
		else:
			if endianness is None:
				endianness = byteorder
			buf = Buffer.from_bytes(byteorder=endianness)
			for opt in opts:
				opt.write_to_buffer(buf)
			EndOfOptions.build().write_to_buffer(buf)
			return bytes(buf)


class EndOfOptions(Option):

	OPT_CODE = OPTION_TYPE_ENDOFOPT


class StringOption(Option):

	@property
	def value(self) -> str:
		return self._value.decode()

	@value.setter
	def value(self, x: str):
		self.set_value(x.encode())


class Comment(StringOption):

	OPT_CODE = OPTION_TYPE_COMMENT


class IfName(StringOption):

	OPT_CODE = OPTION_TYPE_IF_NAME


class IfDescription(StringOption):

	OPT_CODE = OPTION_TYPE_IF_DESCRIPTION


class IfIPv4Address(Option):

	OPT_CODE = OPTION_TYPE_IF_IPV4ADDR

	@property
	def value(self) -> Tuple[IPv4Address, IPv4Address]:
		"""Getter method.

		Returns:
			The pair ip address and netmask.
		
		"""
		return IPv4Address(self._value[0:4]), IPv4Address(self._value[4:])

	@value.setter
	def value(self, x: Tuple[IPv4Address, IPv4Address]):
		"""Setter method.

		Args:
			x: the pair ip address and netmask.

		"""
		self.set_value(x[0].packed + x[1].packed)


class IfIPv6Address(Option):

	OPT_CODE = OPTION_TYPE_IF_IPV6ADDR

	@property
	def value(self) -> IPv6Network:
		return IPv6Network("{}/{}".format(IPv6Address(self._value[0:16]), self._value[16]))

	@value.setter
	def value(self, x: IPv6Network):
		# byte order doesn't matter for one byte
		self.set_value(x.network_address.packed + x.prefixlen.to_bytes(1, byteorder="big"))


class IfMACAddress(Option):

	OPT_CODE = OPTION_TYPE_IF_MACADDR

	@property
	def value(self) -> MACAddress:
		return MACAddress(self._value)

	@value.setter
	def value(self, x: MACAddress):
		self.set_value(x.packed)


class Block(Frame):
	"""General block structure.

	Attributes:
		type: block type.
		length: total block length.
		body: body of the block.

	"""
	__slots__ = ("type", "length", "body")

	BYTEORDER = byteorder

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


class BlockWithOptions(Block):
	"""General block containing options.

	Attributes:
		options: the options as bytes.

	"""
	__slots__ = ("options")

	def get_options(self, endianness: str = byteorder) -> List[Option]:
		return Option.decode(self.options, endianness)


class SectionHeader(BlockWithOptions):
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
	__slots__ = ("byte_order_magic", "major", "minor", "section_length")

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
			raise EndiannessError("Incorrect endianness for this buffer.")
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
	def build(cls, options: List[Option] = None, section_length: int = 0xffffffffffffffff) -> "SectionHeader":
		x = cls()
		x.type = BLOCK_TYPE_SECTION_HEADER
		x.byte_order_magic = BYTE_ORDER_MAGIC
		x.major = 1
		x.minor = 0
		x.section_length = section_length
		x.options = Option.encode(options)
		x.length = 28 + len(x.options)
		return x

	def __str__(self):
		return "SectionHeader {}.{}".format(self.major, self.minor)


class InterfaceDescription(BlockWithOptions):
	"""Interface Description block.

	Attributes:
		type: block type.
		length: block length.
		linktype: linktype.
		snaplen: max number of bytes captured for each packet.
		options: options.

	"""
	__slots__ = ("linktype", "reserved", "snaplen")

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
	def build(cls, linktype: int, snaplen: int, options: List[Option] = None) -> "SectionHeader":
		x = cls()
		x.type = BLOCK_TYPE_INTERFACE_DESCRIPTION
		x.linktype = linktype
		x.reserved = 0
		x.snaplen = snaplen
		x.options = Option.encode(options)
		x.length = 20 + len(x.options)
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
		x.pad = buf.read(count_pad_32(x.original_packet_length))
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
		x.pad = bytes(count_pad_32(x.original_packet_length))
		x.length = 16 + len(data) + len(x.pad)
		return x

	def __str__(self):
		return "SimplePacket - Size {}".format(self.original_packet_length)


class EnhancedPacket(BlockWithOptions):
	"""Enhanced Packet block.

	Attributes:
		type: block type.
		length: block length.
		interface_id: interface on which this packet was received or transmitted.
			There must be a Interface Description block specifying the same id in
			the same section.
		timestamp_high: high 32-bit word of the capture timestamp.
		timestamp_low: low 32-bit word of the capture timestamp.
		captured_packet_length: length of the packet in the field data.
		original_packet_length: original packet size; it can differ from the
			captured length if the packet was truncated in the sniffing process.
		data: packet.
		options: options.

	"""
	__slots__ = ("interface_id", "timestamp_high", "timestamp_low", "captured_packet_length", 
		"original_packet_length", "data", "pad")

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		x = cls()
		# General
		x.type = buf.read_int()
		if x.type != BLOCK_TYPE_ENHANCED_PACKET_BLOCK:
			raise ValueError("Incorrect block type value {}".format(x.type))
		x.length = buf.read_int()
		# Specific
		x.interface_id = buf.read_int()
		x.timestamp_high = buf.read_int()
		x.timestamp_low = buf.read_int()
		x.captured_packet_length = buf.read_int()
		x.original_packet_length = buf.read_int()
		x.data = buf.read(x.captured_packet_length)
		pad_size = count_pad_32(x.captured_packet_length)
		x.pad = buf.read(pad_size)
		x.options = buf.read(x.length - 32 - x.captured_packet_length - pad_size)
		# General
		assert buf.read_int() == x.length
		return x

	def write_to_buffer(self, buf: Buffer):
		# General
		buf.write_int(self.type)
		buf.write_int(self.length)
		# Specific
		buf.write_int(self.interface_id)
		buf.write_int(self.timestamp_high)
		buf.write_int(self.timestamp_low)
		buf.write_int(self.captured_packet_length)
		buf.write_int(self.original_packet_length)
		buf.write(self.data)
		buf.write(self.pad)
		buf.write(self.options)
		# General
		buf.write_int(self.length)

	@classmethod
	def build(cls, interface_id: int, data: bytes, timestamp: int = None, original_size: int = None, options: List[Option] = None) -> "SectionHeader":
		x = cls()
		x.type = BLOCK_TYPE_ENHANCED_PACKET_BLOCK
		x.interface_id = interface_id
		x.timestamp_high = ( timestamp & 0xffffffff00000000 ) >> 32
		x.timestamp_low = timestamp & 0x00000000ffffffff
		x.captured_packet_length = len(data)
		x.original_packet_length = original_size if original_size is not None else x.captured_packet_length
		x.data = data
		padsize = count_pad_32(x.captured_packet_length)
		x.pad = bytes(padsize)
		x.options = Option.encode(options)
		x.length = 32 + x.captured_packet_length + padsize + len(x.options)
		return x

	def __str__(self):
		return "EnhancedPacket - Size {}".format(self.captured_packet_length)


BLOCK_MAP = {
	BLOCK_TYPE_SECTION_HEADER: SectionHeader,
	BLOCK_TYPE_INTERFACE_DESCRIPTION: InterfaceDescription,
	BLOCK_TYPE_SIMPLE_PACKET_BLOCK: SimplePacket,
	BLOCK_TYPE_ENHANCED_PACKET_BLOCK: EnhancedPacket
}


OPTION_MAP = {
	OPTION_TYPE_ENDOFOPT: EndOfOptions,
	OPTION_TYPE_COMMENT: Comment,
	OPTION_TYPE_IF_NAME: IfName,
	OPTION_TYPE_IF_DESCRIPTION: IfDescription,
	OPTION_TYPE_IF_MACADDR: IfMACAddress,
	OPTION_TYPE_IF_IPV4ADDR: IfIPv4Address,
	OPTION_TYPE_IF_IPV6ADDR: IfIPv6Address
}


def get_next_block_class(buf: Buffer):
	"""Returns the class needed to parse the next block in
	a buffer.

	Args:
		buf: buffer to parse.

	Returns:
		A block subclass.

	"""
	buf.mark()
	k = BLOCK_MAP.get(buf.read_int(), Block)
	buf.restore()
	return k


def get_next_option_class(buf: Buffer):
	"""Returns the class needed to parse the next option in
	a buffer.

	Args:
		buf: buffer to parse.

	Returns:
		An Option subclass.

	"""
	buf.mark()
	k = OPTION_MAP.get(buf.read_short(), Option)
	buf.restore()
	return k


def count_pad_32(number_of_octects: int) -> int:
	"""Counts the number of bytes needed to pad data of a
	given length to a size multiple of 32 bits.

	Args:
		number_of_octects: size of the data.

	Returns:
		Number of bytes to add as padding.

	"""
	t = number_of_octects % 4
	return 0 if t == 0 else 4 - t

