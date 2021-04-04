from io import BytesIO


class EndOfBufferError:
	pass


class Buffer:

	@classmethod
	def from_bytes(cls, data: bytes = b''):
		return cls(BytesIO(data))

	def __init__(self, buf: BytesIO):
		self._buf = buf
	
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
		self._buf.seek(0) # use rewind instead (?)
		return self._buf.read()

	def rewind(self):
		self._buf.seek(0)


class Frame:

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		raise NotImplementedError()

	def write_to_buffer(self, buf: Buffer):
		raise NotImplementedError()
