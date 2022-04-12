from typing import Dict
from agave.core.buffer import Buffer, EndOfBufferError


PARAM_SSID_PARAMETER_SET = 0


class TaggedParameter:

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
	

TaggedParameterMap = {
	PARAM_SSID_PARAMETER_SET: SSIDTaggedParameter
}

