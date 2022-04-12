from typing import Dict, List, Tuple
from agave.core.buffer import Buffer, EndOfBufferError


PARAM_SSID_PARAMETER_SET = 0
PARAM_RSN_INFORMATION = 48


class TaggedParameter:

	__slots__ = ("number", "length", "data")

	def __init__(self, number: int, length: int, data: bytes):
		self.number: int = number
		self.length: int = length
		self.data: bytes = data

	@classmethod
	def parse_all(cls, buf: Buffer) -> Dict[int, "TagParameter"]:
		tags = {}
		try:
			while True:
				number = buf.read_byte()
				length = buf.read_byte()
				data = buf.read(length)
				tags[number] = TaggedParameterMap.get(number, cls)(number, length, data)
		except EndOfBufferError:
			pass
		finally:
			return tags


class SSIDTaggedParameter(TaggedParameter):

	@property
	def SSID(self) -> str:
		return self.data.decode()


class RSNTaggedParameter(TaggedParameter):

	def __init__(self, *args):
		super().__init__(*args)
		self.buf = Buffer.from_bytes(self.data)

	@property
	def version(self) -> int:
		return int.from_bytes(self.data[:2], byteorder="little")

	@property
	def group_cipher_suite_OUI(self) -> bytes:
		return self.data[2:5]

	@property
	def group_cipher_suite_type(self) -> int:
		return self.data[5]

	@property
	def pairwise_cipher_suit_count(self) -> int:
		return int.from_bytes(self.data[6:8], byteorder="little")

	def get_pairwise_cipher_suit_list(self) -> List[Tuple[bytes, int]]:
		output = []
		c = self.pairwise_cipher_suit_count
		begin = 8
		for i in range(0, c*4, 4):
			output.append((self.data[begin+i:begin+i+3], self.data[begin+i+3]))
		return output

	@property
	def auth_key_management_count(self) -> int:
		offset = 8 + self.pairwise_cipher_suit_count * 4
		return int.from_bytes(self.data[offset:offset+1], byteorder="little")

	def get_auth_key_management_list(self) -> List[Tuple[bytes, int]]:
		output = []
		c = self.auth_key_management_count
		begin = 10 + self.pairwise_cipher_suit_count * 4
		for i in range(0, c*4, 4):
			output.append((self.data[begin+i:begin+i+3], self.data[begin+i+3]))
		return output

	@property
	def capabilities(self) -> int:
		offset = 10 + (self.auth_key_management_count + self.pairwise_cipher_suit_count) * 4
		return self.data[offset]
	

TaggedParameterMap = {
	PARAM_SSID_PARAMETER_SET: SSIDTaggedParameter,
	PARAM_RSN_INFORMATION: RSNTaggedParameter
}

