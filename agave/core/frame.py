from .buffer import Buffer


class Frame:

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		raise NotImplementedError()

	def write_to_buffer(self, buf: Buffer):
		raise NotImplementedError()


class FrameWithChecksum(Frame):

	def compute_checksum(self):
		raise NotImplementedError()

	def set_checksum(self):
		self.checksum = 0
		self.checksum = self.compute_checksum()

	def compute_checksum_from_buffer(self, buf: Buffer, words: int):
		"""
		PARAMS
			buf: the data required by the protocol to compute it's checksum.
			words: the number of 16 bits words that need to be read from the buffer.
		"""
		csum = 0
		for i in range(0, words):
			csum += buf.read_short()
		while (csum & 0xff0000) != 0:
			carry = ( csum & 0xff0000 ) >> 16
			csum = csum & 0x00ffff
			csum += carry
		return 0xffff - csum

	def is_checksum_valid(self):
		return self.compute_checksum() == 0
