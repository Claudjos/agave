from .frame import FrameWithChecksum, bit_property
from .buffer import Buffer


class TCP(FrameWithChecksum):
	"""TCP Header.
	
	Attributes:
		source (int): source port.
		destination (int): destination port.
		sequence_number (int): sequence number.
		ack_number (int): acknowledgment number.
		_offset_ns (int): the byte containing data offset, reserved, 
			and the NS flag.
		_flags (int): the byte containing the flags (except for NS).
		window_size(int): window size.
		checksum (int): checksum.
		urgent_pointer(int): urgent pointer.
		_options (bytes): unparsed options.

	"""
	__slots__ = ("source", "destination", "sequence_number", "ack_number",
		"_offset_ns", "_flags", "window_size", "checksum", "urgent_pointer",
		"_options")

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "TCP":
		x = TCP()
		x.source = buf.read_short()
		x.destination = buf.read_short()
		x.sequence_number = buf.read_int()
		x.ack_number = buf.read_int()
		x._offset_ns = buf.read_byte()
		x._flags = buf.read_byte()
		x.window_size = buf.read_short()
		x.checksum = buf.read_short()
		x.urgent_pointer = buf.read_short()
		x._options = buf.read(4 * (x.data_offset - 5))
		return x

	def write_to_buffer(self, buf: Buffer):
		buf.write_short(self.source)
		buf.write_short(self.destination)
		buf.write_int(self.sequence_number)
		buf.write_int(self.ack_number)
		buf.write_byte(self._offset_ns)
		buf.write_byte(self._flags)
		buf.write_short(self.window_size)
		buf.write_short(self.checksum)
		buf.write_short(self.urgent_pointer)
		buf.write(self._options)

	@property
	def data_offset(self) -> int:
		"""TCP Header length in 32 bit words."""
		return (self._offset_ns & 0xf0) >> 4

	@data_offset.setter
	def data_offset(self, x: int):
		self._offset_ns &= 0x0f
		self._offset_ns |= (x << 4) & 0xf0

	ns  = bit_property("_offset_ns", 0x01, "ECN Nonce.")
	cwr = bit_property("_flags", 0x80, "Congestion Window Reduced.")
	ece = bit_property("_flags", 0x40, "ECN Echo.")
	urg = bit_property("_flags", 0x20, "Urgent pointer field is significant.")
	ack = bit_property("_flags", 0x10, "Acknowledgment number field is significant.")
	psh = bit_property("_flags", 0x08, "Push buffered data to receiving application.")
	rst = bit_property("_flags", 0x04, "Reset connection.")
	syn = bit_property("_flags", 0x02, "Synchronize sequence numbers.")
	fin = bit_property("_flags", 0x01, "Finalize.")

