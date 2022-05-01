from .frame import FrameWithChecksum
from .buffer import Buffer


class UDP(FrameWithChecksum):
	"""UDP Header.
	
	Attributes:
		source (int): source port.
		destination (int): destination port.
		length (int): header + payload length in bytes.
		checksum (int): checksum.

	"""
	__slots__ = ("source", "destination", "length", "checksum")

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "UDP":
		x = UDP()
		x.source = buf.read_short()
		x.destination = buf.read_short()
		x.length = buf.read_short()
		x.checksum = buf.read_short()
		return x

	def write_to_buffer(self, buf: Buffer):
		buf.write_short(self.source)
		buf.write_short(self.destination)
		buf.write_short(self.length)
		buf.write_short(self.checksum)

