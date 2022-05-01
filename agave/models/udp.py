from .frame import Frame, compute_checksum_from_bytes
from .buffer import Buffer


class UDP(Frame):
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

	def compute_checksum(self, pseudo_header: bytes, payload: bytes) -> int:
		"""Computes the UDP checksum."""
		t = self.checksum
		self.checksum = 0
		c = compute_checksum_from_bytes(pseudo_header + bytes(self) + payload)
		self.checksum = t
		return c

