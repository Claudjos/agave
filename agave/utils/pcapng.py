"""PCAP Next Generation.
Utilities to parse/dump packets from/to file.

"""
import time
from sys import byteorder
from agave.models.pcapng import *
from agave.models.buffer import EndOfBufferError
from agave.nic.interfaces import NetworkInterface
from typing import Iterator, Tuple
from ipaddress import IPv6Network


class BufferedDumper:
	"""Basic class to dump packets to pcapng file. Useful for debug."""
	__slots__ = ("buf", "current_interfaces", "current_interfaces_count")

	def __init__(self, buf: Buffer):
		self.buf = buf

	def start_section(self):
		"""Adds a section block."""
		SectionHeader.build().write_to_buffer(self.buf)
		self.current_interfaces = {}
		self.current_interfaces_count = 0

	def add_network_interface(self, interface: NetworkInterface, linktype: int, snaplen: int):
		"""Adds an Interface Description block. Additionally to BufferedDumper.add_interface,
		it adds options specifying interface name, MAC, IPv4, and IPv6.

		Args:
			interface: network interface.
			linktype: linktype value.
			snaplen: max size for a packet; equal to max size read from a socket.

		"""
		options = [
			IfName.build(interface.name),
			IfMACAddress.build(interface.mac),
		]
		if interface.ip is not None:
			options.append(IfIPv4Address.build((interface.ip, interface.network.netmask)))
		if interface.ipv6 is not None:
			options.append(IfIPv6Address.build(IPv6Network(interface.ipv6)))
		self.add_interface(interface.name, linktype, snaplen, options=options)


	def add_interface(self, interface_id: str, linktype: int, snaplen: int, options: List[Option] = None):
		"""Adds an Interface Description block.

		Args:
			interface_id: id used by the user to refer to this interfaces. For example,
				the name, or the id, or the address.
			linktype: linktype value.
			snaplen: max size for a packet; equal to max size read from a socket.

		"""
		InterfaceDescription.build(linktype=linktype, snaplen=snaplen, options=options).write_to_buffer(self.buf)
		self.current_interfaces[interface_id] = self.current_interfaces_count
		self.current_interfaces_count += 1

	def dump(self, packet: bytes):
		"""Dumps a packet as a Simple Block.
		
		Args:
			packet: packet as bytes.

		"""
		SimplePacket.build(packet).write_to_buffer(self.buf)

	def edump(self, interface_id: int, packet: bytes, timestamp: int = None, comment: str = None) -> "SectionHeader":
		"""Dumps a packet as a Enhanced Block.

		Args:
			interface_id: id used by the user to refer to this interfaces. For example,
				the name, or the id, or the address.
			packet: packet as bytes.
			timestamp: timestamp; resolution is assumed in micro seconds (at lest as long
				as support for 'option' is added to this module). Default to now.
			comment: comment to add to the block as option.
		
		"""
		if timestamp is None:
			timestamp = int(time.time() * 1000000)
		options = [Comment.build(comment)] if comment is not None else None
		EnhancedPacket.build(self.current_interfaces[interface_id], packet, timestamp=timestamp,
			options=options).write_to_buffer(self.buf)


class BufferedLoader:
	"""Basic class to load packets from pcapng file. Useful for debug."""
	__slots__ = ("buf", "current_header", "current_interfaces")

	def __init__(self, buf: Buffer):
		self.buf = buf

	def get_section_byte_order(self) -> str:
		return self.buf.byteorder

	def get_interface_by_id(self, interface_id: int) -> InterfaceDescription:
		return self.current_interfaces[interface_id]

	def stream_section(self) -> Iterator[Tuple[int, bytes]]:
		"""Streams packet from a PCAPNG file.

		Yields:
			Interface id, data.

		"""
		try:
			try:
				self.buf.mark()
				self.current_interfaces = []
				self.current_header = SectionHeader.read_from_buffer(self.buf)
			except EndiannessError:
				self.buf.restore()
				self.buf.invert_byteorder()
				self.current_header = SectionHeader.read_from_buffer(self.buf)
		except ValueError:
			self.buf.restore()
			raise ValueError("Buffer should start from an Header Section")
		try:
			while True:
				block = get_next_block_class(self.buf).read_from_buffer(self.buf)
				# print(block)
				if isinstance(block, InterfaceDescription):
					self.current_interfaces.append(block)
				elif isinstance(block, SimplePacket):
					yield (0, block.data)
				elif isinstance(block, EnhancedPacket):
					yield (block.interface_id, block.data)
				elif isinstance(block, SectionHeader):
					# Moves back to start of the block and stops the stream
					self.buf.seek(self.buf.tell - block.length)
					return
				else:
					# silently ignore other block for now
					pass
		except EndOfBufferError:
			# File end or parsing error
			return
		

class StreamDumper(BufferedDumper):

	__slots__ = ("stream")

	def __init__(self, stream):
		super().__init__(Buffer(stream, byteorder))
		self.stream = stream

	@classmethod
	def from_file(cls, path: str):
		return cls(open(path, "wb"))

	def __enter__(self):
		self.stream.__enter__()
		return self

	def __exit__(self, *args, **kwargs):
		return self.stream.__exit__(*args, **kwargs)


class StreamLoader(BufferedLoader):

	__slots__ = ("stream")

	def __init__(self, stream):
		super().__init__(Buffer(stream, byteorder))
		self.stream = stream

	@classmethod
	def from_file(cls, path: str):
		return cls(open(path, "rb"))

	def __enter__(self):
		self.stream.__enter__()
		return self

	def __exit__(self, *args, **kwargs):
		return self.stream.__exit__(*args, **kwargs)

