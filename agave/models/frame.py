from .buffer import Buffer


class Frame:

	__slots__ = ()

	BYTEORDER = "big"	# Network byte order

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		raise NotImplementedError()

	def write_to_buffer(self, buf: Buffer):
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, data: bytes) -> "Frame":
		return cls.read_from_buffer(Buffer.from_bytes(data, byteorder=cls.BYTEORDER))

	def __bytes__(self) -> bytes:
		buf = Buffer.from_bytes(byteorder=self.BYTEORDER)
		self.write_to_buffer(buf)
		return bytes(buf)


class FrameWithChecksum(Frame):

	__slots__ = ("checksum")

	def _compute_checksum(self, pseudo_header: bytes, payload: bytes) -> int:
		return compute_checksum_from_bytes(pseudo_header + bytes(self) + payload)

	def is_checksum_valid(self, pseudo_header: bytes = b'', payload: bytes = b'') -> bool:
		return self._compute_checksum(pseudo_header, payload) == 0

	def set_checksum(self, pseudo_header: bytes = b'', payload: bytes = b''):
		self.checksum = 0
		self.checksum = self._compute_checksum(pseudo_header, payload)


def compute_checksum_from_bytes(data: bytes) -> int:
	return compute_checksum_from_buffer(
		Buffer.from_bytes(data), int(len(data) / 2))


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


def bit_getter(field: int, bitmask: int) -> int:
	def t(self) -> bool:
		return getattr(self, field) & bitmask == bitmask
	return t


def bit_setter(field: int, bitmask: int):
	def t(self, x: bool):
		data = getattr(self, field)
		data &= ~bitmask
		if x:
			data |= bitmask
		setattr(self, field, data)
	return t


def bit_property(field: str, bitmask: int, docstring: str):
	return property(
		bit_getter(field, bitmask),
		bit_setter(field, bitmask),
		None,
		docstring
	)

