"""Neighbor Discovery for IP version 6 (IPv6), RFC 4861."""
from typing import Tuple, List
from ..frame import bit_property
from ..buffer import Buffer
from ..ethernet import MACAddress
from .icmpv6 import (
	ICMPv6, TYPE_NEIGHBOR_ADVERTISEMENT, TYPE_NEIGHBOR_SOLICITATION,
	TYPE_ROUTER_ADVERTISEMENT, TYPE_ROUTER_SOLICITATION
)
from ipaddress import IPv6Address, IPv6Network


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
			bytes(self.body)
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


class MTU(Option):

	@property
	def mtu(self):
		return int.from_bytes(self.body[2:], byteorder="big")

	@mtu.setter
	def mtu(self, x: int):
		self.body = b'\x00\x00' + x.to_bytes(4, byteorder="big")

	@classmethod
	def build(cls, mtu: int) -> "MTU":
		t = cls(NDP_OPTION_TYPE_MTU, 1, b'')
		t.mtu = mtu
		return t


class PrefixInformation(Option):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		if isinstance(self.body, bytes):
			self.body = Buffer.from_bytes(self.body)

	@property
	def prefix_length(self) -> int:
		self.body.seek(0)
		return self.body.read_byte()

	@property
	def l_flag(self) -> bool:
		self.body.seek(1)
		return int(self.body.read_byte()) & 0x80 > 0

	@property
	def a_flag(self) -> bool:
		self.body.seek(1)
		return int(self.body.read_byte()) & 0x40 > 0

	@property
	def valid_lifetime(self) -> int:
		self.body.seek(2)
		return self.body.read_int()

	@property
	def preferred_lifetime(self) -> int:
		self.body.seek(6)
		return self.body.read_int()

	@property
	def reserved_2(self) -> int:
		self.body.seek(10)
		return self.body.read_int()

	@property
	def prefix(self) -> bytes:
		self.body.seek(14)
		return self.body.read(16)

	@prefix_length.setter
	def prefix_length(self, x: int):
		self.body.seek(0)
		self.body.write_byte(x)

	@l_flag.setter
	def l_flag(self, x: bool):
		self.body.seek(1)
		t = int(self.body.read_byte())
		t |= 0x80 if x else 0
		self.body.seek(1)
		self.body.write_byte(t)

	@a_flag.setter
	def a_flag(self, x: bool):
		self.body.seek(1)
		t = int(self.body.read_byte())
		t |= 0x40 if x else 0
		self.body.seek(1)
		self.body.write_byte(t)

	@valid_lifetime.setter
	def valid_lifetime(self, x: int):
		self.body.seek(2)
		self.body.write_int(x)

	@preferred_lifetime.setter
	def preferred_lifetime(self, x: int):
		self.body.seek(6)
		self.body.write_int(x)

	@reserved_2.setter
	def reserved_2(self, x: int):
		self.body.seek(10)
		self.body.write_int(x)

	@prefix.setter
	def prefix(self, x: bytes):
		self.body.seek(14)
		self.body.write(x)

	@classmethod
	def build(cls, network: IPv6Network, valid_lifetime: int, preferred_lifetime: int,
		l: bool = False, a: bool = False) -> "PrefixInformation":
		"""Builds an instance of the class."""
		t = cls(NDP_OPTION_TYPE_PREFIX_INFORMATION, 4, bytes(30))
		t.prefix_length = network.prefixlen
		t.prefix = network.network_address.packed
		t.valid_lifetime = valid_lifetime
		t.preferred_lifetime = preferred_lifetime
		t.l_flag = l
		t.a_flag = a
		return t


class NDP:

	__slots__ = ()

	OPTION_TO_CLASS = {
		NDP_OPTION_TYPE_SOURCE_LINK_LAYER_ADDRESS: LinkLayerAddress,
		NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS: LinkLayerAddress,
		NDP_OPTION_TYPE_MTU: MTU,
		NDP_OPTION_TYPE_PREFIX_INFORMATION: PrefixInformation
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

	@classmethod
	def map_multicast_over_ethernet(cls, ip: IPv6Address) -> MACAddress:
		"""Maps a IPv6 multicast address to a MAC address 33-33-XX-XX-XX-XX
		as for RFC 2464.

		Args:
			ip: a multicast IPv6 address.

		Returns:
			The MAC address.
		"""
		return MACAddress(b'\x33\x33' + ip.packed[12:])


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

	@classmethod
	def compute_solicited_node_multicast_address(cls, x: IPv6Address) -> IPv6Address:
		"""Returns the solicited node multicast address as for RFC 4291.

		Args:
			x: a unicast or anycast IPv6 address.

		Returns:
			An IPv6 composed by the first 104 bit (13 bytes) of the Solicited-Node
			Address and the last 24 bit (3 bytes) of the input address.

		Note:
			Solicited-Node Address: FF02:0:0:0:0:1:FFXX:XXXX.

		"""
		return IPv6Address(b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff' + x.packed[13:])


class NeighborAdvertisement(NeighborMessage):

	ICMP_TYPE = TYPE_NEIGHBOR_ADVERTISEMENT

	router_flag = bit_property("reserved", 0x80000000, "Router Flag")
	solicited_flag = bit_property("reserved", 0x40000000, "Solicited Flag")
	override_flag = bit_property("reserved", 0x20000000, "Override Flag")


class RouterSolicitation(NDP):

	__slots__ = ("options")

	def __init__(self, options: List[Option] = None):
		self.options = options if options is not None else []

	@classmethod
	def parse(cls, frame: ICMPv6) -> "NeighborMessage":
		options_size = len(frame.body) - 4
		buf = Buffer.from_bytes(frame.body)
		buf.read_int()
		return cls(options=cls.read_options(buf, options_size))

	def to_frame(self) -> ICMPv6:
		return ICMPv6(
			TYPE_ROUTER_SOLICITATION, 0, 0, b'\x00\x00\x00\x00' + self.options_packed(self.options)
		)


class RouterAdvertisement(NDP):

	def __init__(self, cur_hop_limit: int = 1, reserved: int = 0, lifetime: int = 0,
		reachable_time: int = 0, retrans_timer: int = 0, options: List[Option] = None,
		m: bool = None, o: bool = None
	):
		self.options: List[Option] = options if options is not None else []
		self.cur_hop_limit: int = cur_hop_limit
		self.reserved: int = reserved
		self.lifetime: int = lifetime
		self.reachable_time: int = reachable_time
		self.retrans_timer: int = retrans_timer
		if m is not None:
			self.m_flag = m
		if o is not None:
			self.o_flag = o

	@classmethod
	def parse(cls, frame: ICMPv6) -> "RouterAdvertisement":
		options_size = len(frame.body) - 12
		buf = Buffer.from_bytes(frame.body)
		cur_hop_limit = buf.read_byte()
		reserved = buf.read_byte()
		lifetime = buf.read_short()
		reachable_time = buf.read_int()
		retrans_timer = buf.read_int()
		return cls(cur_hop_limit, reserved, lifetime, reachable_time, retrans_timer,
			options=cls.read_options(buf, options_size))

	def to_frame(self) -> ICMPv6:
		buf = Buffer.from_bytes()
		buf.write_byte(self.cur_hop_limit)
		buf.write_byte(self.reserved)
		buf.write_short(self.lifetime)
		buf.write_int(self.reachable_time)
		buf.write_int(self.retrans_timer)
		return ICMPv6(TYPE_ROUTER_ADVERTISEMENT, 0, 0, bytes(buf) + 
			self.options_packed(self.options))

	m_flag = bit_property("reserved", 0x80, "M Flag")
	o_flag = bit_property("reserved", 0x40, "O Flag")

