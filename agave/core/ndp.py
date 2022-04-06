"""Neighbor Discovery for IP version 6 (IPv6), RFC 4861."""
from typing import Tuple, List
from .ethernet import MACAddress
from .icmpv6 import ICMPv6, TYPE_NEIGHBOR_ADVERTISEMENT, TYPE_NEIGHBOR_SOLICITATION
from .buffer import Buffer
from ipaddress import IPv6Address


# NDP option types
NDP_OPTION_TYPE_SOURCE_LINK_LAYER_ADDRESS = 1
NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS = 2
NDP_OPTION_TYPE_PREFIX_INFORMATION = 3
NDP_OPTION_TYPE_REDIRECTED_HEADER = 4
NDP_OPTION_TYPE_MTU = 5


class Option:

	__slots__ = ("type", "length", "body")

	def __init__(self, _type: int, length: int, body: bytes):
		self.type = _type
		self.length = length
		self.body = body

	def __bytes__(self):
		return (
			self.type.to_bytes(1, byteorder="big") +
			self.length.to_bytes(1, byteorder="big") +
			self.body
		)


class LinkLayerAddress(Option):
	
	OPT_TYPE = 0

	@property
	def mac(self):
		return MACAddress(self.body)

	@mac.setter
	def mac(self, x: MACAddress):
		self.body = x.packed

	@classmethod
	def build(cls, mac: MACAddress) -> "LinkLayerAddress":
		return cls(cls.OPT_TYPE, 1, mac.packed)


class SourceLinkLayerAddress(LinkLayerAddress):

	OPT_TYPE = NDP_OPTION_TYPE_SOURCE_LINK_LAYER_ADDRESS


class TargetLinkLayerAddress(LinkLayerAddress):

	OPT_TYPE = NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS


class NDP:

	__slots__ = ()

	OPTION_TO_CLASS = {
		NDP_OPTION_TYPE_SOURCE_LINK_LAYER_ADDRESS: LinkLayerAddress,
		NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS: LinkLayerAddress,
	}

	@classmethod
	def parse(cls, frame: ICMPv6):
		raise NotImplementedError()

	def to_frame(self) -> ICMPv6:
		raise NotImplementedError()

	@classmethod
	def read_options(cls, buf: Buffer, size: int) -> List[Option]:
		options = []
		while size > 0:
			o, r = cls.read_option(buf)
			options.append(o)
			size -= r
		return options

	@classmethod
	def read_option(cls, buf: Buffer) -> Tuple[Option, int]:
		"""Builder for Option."""
		opt_type = buf.read_byte()
		opt_len = buf.read_byte()
		body_len = opt_len * 8
		opt_body = buf.read(body_len - 2)
		klass = cls.OPTION_TO_CLASS.get(opt_type, Option)
		return klass(opt_type, opt_len, opt_body), body_len

	@classmethod
	def options_packed(cls, options: List[Option]) -> bytes:
		t = b''
		for o in options:
			t += bytes(o)
		return t


class NeighborMessage(NDP):

	__slots__ = ("target", "options", "reserved")

	ICMP_TYPE = 0

	def __init__(self, target: IPv6Address, options: List[Option] = None, reserved: int = 0):
		self.target = target
		self.options = options if options is not None else []
		self.reserved = reserved

	@classmethod
	def parse(cls, frame: ICMPv6) -> "NeighborMessage":
		options_size = len(frame.body) - 20
		buf = Buffer.from_bytes(frame.body)
		reserved = buf.read_int()
		return cls(
			IPv6Address(buf.read(16)),
			options=cls.read_options(buf, options_size),
			reserved=reserved
		)

	def to_frame(self) -> ICMPv6:
		return ICMPv6(self.ICMP_TYPE, 0, 0, (
			self.reserved.to_bytes(4, byteorder="big") +
			self.target.packed +
			self.options_packed(self.options)
		))


class NeighborSolicitation(NeighborMessage):

	ICMP_TYPE = TYPE_NEIGHBOR_SOLICITATION


class NeighborAdvertisment(NeighborMessage):

	ICMP_TYPE = TYPE_NEIGHBOR_ADVERTISEMENT

	@property
	def router_flag(self) -> bool:
		return self.reserved & 0x80000000 > 0

	@property
	def solicited_flag(self) -> bool:
		return self.reserved & 0x40000000 > 0

	@property
	def override_flag(self) -> bool:
		return self.reserved & 0x20000000 > 0

	@router_flag.setter
	def router_flag(self, x: bool):
		self.reserved |= 0x80000000 if x else 0

	@solicited_flag.setter
	def solicited_flag(self, x: bool):
		self.reserved |= 0x40000000 if x else 0

	@override_flag.setter
	def override_flag(self, x: bool):
		self.reserved |= 0x20000000 if x else 0

