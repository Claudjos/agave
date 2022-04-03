from .buffer import Buffer


class Frame:

	__slots__ = ()

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		raise NotImplementedError()

	def write_to_buffer(self, buf: Buffer):
		raise NotImplementedError()


class FrameWithChecksum(Frame):

	__slots__ = ()

	def compute_checksum(self):
		raise NotImplementedError()

	def set_checksum(self):
		self.checksum = 0
		self.checksum = self.compute_checksum()

	def compute_checksum_from_buffer(self, buf: Buffer, words: int):
		return compute_checksum_from_buffer(buf, words)

	def is_checksum_valid(self):
		return self.compute_checksum() == 0


def compute_checksum_from_buffer(buf: Buffer, words: int) -> int:
	"""Compute checksum RFC 1071.

	Args:
		buf: the data required by the protocol to compute it's checksum.
		words: the number of 16 bits words that need to be read from the
			buffer.

	Returns:
		The checksum.

	"""
	csum = 0
	for i in range(0, words):
		csum += buf.read_short()
	while (csum & 0xff0000) != 0:
		carry = ( csum & 0xff0000 ) >> 16
		csum = csum & 0x00ffff
		csum += carry
	return 0xffff - csum
