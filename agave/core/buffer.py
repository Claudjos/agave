from io import BytesIO


class EndOfBufferError(Exception):
	pass


class Buffer:

	__slots__ = ("_buf", "_mark")

	@classmethod
	def from_bytes(cls, data: bytes = b''):
		return cls(BytesIO(data))

	def __init__(self, buf: BytesIO):
		self._buf = buf
		self._mark = 0
	
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
		return int.from_bytes(self.read(1), byteorder="big")

	def read_short(self) -> int:
		return int.from_bytes(self.read(2), byteorder="big")

	def read_int(self) -> int:
		return int.from_bytes(self.read(4), byteorder="big")

	def write(self, data: bytes):
		self._buf.write(data)

	def write_byte(self, number: int):
		return self.write(number.to_bytes(1, byteorder="big"))

	def write_short(self, number: int):
		return self.write(number.to_bytes(2, byteorder="big"))

	def write_int(self, number: int):
		return self.write(number.to_bytes(4, byteorder="big"))

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
