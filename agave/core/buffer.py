from io import BytesIO


class EndOfBufferError(Exception):
	pass


class Buffer:

	__slots__ = ("_buf", "_mark", "_byteorder")

	@classmethod
	def from_bytes(cls, data: bytes = b'', byteorder: str = "big"):
		return cls(BytesIO(data), byteorder)

	def __init__(self, buf: BytesIO, byteorder: str):
		self._buf = buf
		self._mark = 0
		self.byteorder = byteorder 	# the property setter will check the value.
	
	def read(self, size: int = 1) -> bytes:
		if size == 0:
			return b''
		else:
			t = self._buf.read(size)
			if t == b'':
				raise EndOfBufferError()
			else:
				return t

	def read_byte(self) -> int:
		return int.from_bytes(self.read(1), byteorder=self._byteorder)

	def read_short(self) -> int:
		return int.from_bytes(self.read(2), byteorder=self._byteorder)

	def read_int(self) -> int:
		return int.from_bytes(self.read(4), byteorder=self._byteorder)

	def read_long(self) -> int:
		return int.from_bytes(self.read(8), byteorder=self._byteorder)

	def write(self, data: bytes):
		self._buf.write(data)

	def write_byte(self, number: int):
		return self.write(number.to_bytes(1, byteorder=self._byteorder))

	def write_short(self, number: int):
		return self.write(number.to_bytes(2, byteorder=self._byteorder))

	def write_int(self, number: int):
		return self.write(number.to_bytes(4, byteorder=self._byteorder))

	def write_long(self, number: int):
		return self.write(number.to_bytes(8, byteorder=self._byteorder))

	def __bytes__(self):
		self._buf.seek(0)
		return self._buf.read()

	def rewind(self):
		self._buf.seek(0)

	def seek(self, index: int):
		self._buf.seek(index)

	def read_remaining(self):
		return self._buf.read()

	def mark(self):
		self._mark = self._buf.tell()

	def restore(self):
		self._buf.seek(self._mark)

	@property
	def byteorder(self) -> str:
		return self._byteorder

	@byteorder.setter
	def byteorder(self, x: str):
		if x != "big" and x != "little":
			raise ValueError("byte order value can be 'little' or 'big'")
		else:
			self._byteorder = x

	def invert_byteorder(self):
		self._byteorder = "big" if self._byteorder == "little" else "little"

