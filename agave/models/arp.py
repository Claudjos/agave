from . import ethernet
from .frame import Frame
from .buffer import Buffer
from .ethernet import MACAddress
from ipaddress import IPv4Address


HARDWARE_TYPE_ETHERNET = 0x0001
PROTOCOL_TYPE_IP = 0x0800

ADDRESS_LEN_ETHERNET = 6
ADDRESS_LEN_IP = 4

OPERATION_REQUEST = 1
OPERATION_REPLY = 2
OPERATION_REQUEST_REVERSE = 3
OPERATION_REPLY_REVERSE = 4


class ARP(Frame):

	__slots__ = (
		"hardware_type", "protocol_type", 
		"hardware_addr_len", "protocol_addr_len",
		"operation",
		"sender_hardware_address", "sender_protocol_address",
		"target_hardware_address", "target_protocol_address"
	)

	def __init__(
		self,
		hardware_type: int, protocol_type: int,
		hardware_addr_len: int, protocol_addr_len: int,
		operation: int,
		sender_hardware_address: bytes, sender_protocol_address: bytes,
		target_hardware_address: bytes, target_protocol_address: bytes
	):
		self.hardware_type = hardware_type
		self.protocol_type = protocol_type
		self.hardware_addr_len = hardware_addr_len
		self.protocol_addr_len = protocol_addr_len
		self.operation = operation
		self.sender_hardware_address = sender_hardware_address
		self.sender_protocol_address = sender_protocol_address
		self.target_hardware_address = target_hardware_address
		self.target_protocol_address = target_protocol_address

	@classmethod
	def read_from_buffer(cls, buf):
		hardware_type = buf.read_short()
		protocol_type = buf.read_short()
		hardware_addr_len = buf.read_byte()
		protocol_addr_len = buf.read_byte()
		operation = buf.read_short()
		sender_hardware_address = buf.read(hardware_addr_len)
		sender_protocol_address = buf.read(protocol_addr_len)
		target_hardware_address = buf.read(hardware_addr_len)
		target_protocol_address = buf.read(protocol_addr_len)
		return cls(
			hardware_type, protocol_type,
			hardware_addr_len, protocol_addr_len,
			operation,
			sender_hardware_address, sender_protocol_address,
			target_hardware_address, target_protocol_address
		)

	def write_to_buffer(self, buf):
		buf.write_short(self.hardware_type)
		buf.write_short(self.protocol_type)
		buf.write_byte(self.hardware_addr_len)
		buf.write_byte(self.protocol_addr_len)
		buf.write_short(self.operation)
		buf.write(self.sender_hardware_address)
		buf.write(self.sender_protocol_address)
		buf.write(self.target_hardware_address)
		buf.write(self.target_protocol_address)

	@classmethod
	def build(
		cls,
		operation: int,
		sender_hardware_address: bytes, sender_protocol_address: bytes,
		target_hardware_address: bytes, target_protocol_address: bytes
	):
		"""
		Build a frame assuming hardware and protocol to be Ethernet and IPv4.
		"""
		return cls(
			HARDWARE_TYPE_ETHERNET, PROTOCOL_TYPE_IP,
			ADDRESS_LEN_ETHERNET, ADDRESS_LEN_IP,
			operation,
			sender_hardware_address, sender_protocol_address,
			target_hardware_address, target_protocol_address
		)

	def reply(self, hardware: bytes) -> bytes:
		"""Builds an ARP reply.

		Args:
			hardware: the hardware address to add to the response.

		Returns:
			A reply message (Ethernet and ARP headers).

		Raises:
			ValueError: if the instance is not a request message.

		"""
		if self.operation != OPERATION_REQUEST:
			raise ValueError("ARP.reply can be called only on request message")
		eth_frame = ethernet.Ethernet(
			self.sender_hardware_address,
			hardware,
			ethernet.ETHER_TYPE_ARP
		)
		arp_frame = self.build(
			OPERATION_REPLY,
			hardware, self.target_protocol_address,
			self.sender_hardware_address, self.sender_protocol_address
		)
		buf = Buffer.from_bytes()
		eth_frame.write_to_buffer(buf)
		arp_frame.write_to_buffer(buf)
		return bytes(buf)

	@classmethod
	def is_at(cls, sender_mac: MACAddress, sender_ipv4: IPv4Address, target_mac: MACAddress,
		target_ipv4: IPv4Address) -> bytes:
		eth_frame = ethernet.Ethernet(
			target_mac.packed,
			sender_mac.packed,
			ethernet.ETHER_TYPE_ARP
		)
		arp_frame = cls.build(
			OPERATION_REPLY,
			sender_mac.packed, sender_ipv4.packed,
			target_mac.packed, target_ipv4.packed
		)
		buf = Buffer.from_bytes()
		eth_frame.write_to_buffer(buf)
		arp_frame.write_to_buffer(buf)
		return bytes(buf)

	@classmethod
	def who_has(cls, target_ipv4: IPv4Address, sender_mac: MACAddress, sender_ipv4: IPv4Address):
		eth_frame = ethernet.Ethernet(
			b'\xff\xff\xff\xff\xff\xff',
			sender_mac.packed,
			ethernet.ETHER_TYPE_ARP
		)
		arp_frame = cls.build(
			OPERATION_REQUEST,
			sender_mac.packed, sender_ipv4.packed,
			b'\x00\x00\x00\x00\x00\x00', target_ipv4.packed
		)
		buf = Buffer.from_bytes()
		eth_frame.write_to_buffer(buf)
		arp_frame.write_to_buffer(buf)
		return bytes(buf)

	@classmethod
	def request_reverse(cls, sender_mac: MACAddress, target_mac: MACAddress) -> bytes:
		eth_frame = ethernet.Ethernet(
			b'\xff\xff\xff\xff\xff\xff',
			sender_mac.packed,
			ethernet.ETHER_TYPE_ARP
		)
		arp_frame = cls.build(
			OPERATION_REQUEST_REVERSE,
			sender_mac.packed, b'\x00\x00\x00\x00',
			target_mac.packed, b'\x00\x00\x00\x00'
		)
		buf = Buffer.from_bytes()
		eth_frame.write_to_buffer(buf)
		arp_frame.write_to_buffer(buf)
		return bytes(buf)
