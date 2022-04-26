import logging
from typing import Dict, List, Tuple
from agave.core.frame import Frame
from agave.core.buffer import Buffer, EndOfBufferError


logger = logging.getLogger(__name__)


PARAM_SSID_PARAMETER_SET = 0
PARAM_SUPPORTED_RATES = 1
PARAM_DS_PARAMETER_SET = 3
PARAM_RSN_INFORMATION = 48


class TaggedParameter:
	"""Base model for a tagged parameter."""
	__slots__ = ("number", "length", "data")

	def __init__(self, number: int, length: int, data: bytes):
		self.number: int = number
		self.length: int = length
		self.data: bytes = data

	def __bytes__(self):
		return (
			self.number.to_bytes(1, byteorder="little") +
			self.length.to_bytes(1, byteorder="little") +
			self.data
		)


class SSID(TaggedParameter):

	@property
	def SSID(self) -> str:
		if self.length == 0:
			return ""
		else:
			return self.data.decode()

	@SSID.setter
	def SSID(self, x: str):
		self.data = x.encode()

	@classmethod
	def build(cls, ssid: str) -> "SSID":
		return cls(PARAM_SSID_PARAMETER_SET, len(ssid), ssid.encode())


class SupportedRates(TaggedParameter):

	@property
	def rates(self) -> List[int]:
		return list(self.data)

	@rates.setter
	def rates(self, rates: List[int]):
		self.data = b''.join(map(lambda x: x.to_bytes(1, byteorder="little"), rates))

	@classmethod
	def build(cls, rates: List[int]) -> "SupportedRates":
		t = cls(PARAM_SUPPORTED_RATES, len(rates), b'')
		t.rates = rates
		return t


class DSParameterSet(TaggedParameter):

	@property
	def channel(self) -> int:
		return int.from_bytes(self.data, byteorder="little")

	@channel.setter
	def channel(self, x: int):
		self.data = x.to_bytes(1, byteorder="little")

	@classmethod
	def build(cls, channel: int) -> "DSParameterSet":
		t = cls(PARAM_DS_PARAMETER_SET, 1, b'\x00')
		t.channel = channel
		return t


class RSN(TaggedParameter):

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
	PARAM_SSID_PARAMETER_SET: SSID,
	PARAM_SUPPORTED_RATES: SupportedRates,
	PARAM_DS_PARAMETER_SET: DSParameterSet,
	PARAM_RSN_INFORMATION: RSN
}


class TaggedParameterNotFound(Exception):
	pass


class TaggedParameters(Frame):
	"""Tagged parameters list."""
	__slots__ = ("_params")

	BYTEORDER = "little"

	def __init__(self):
		self._params = []

	def get(self, x: int, raise_on_miss: bool = True) -> TaggedParameter:
		"""Gets a parameter by number. In case of multiple parameters
		with the same number, the first one is returned.

		Args:
			x: parameter number.
			raise_on_miss: if False, and no parameter is found, no exception is
				raised and None is returned.

		Returns:
			A tagged parameter.

		Raises:
			TaggedParameterNotFound, if no parameter is found with the given
				number.
		"""
		for p in self._params:
			if p.number == x:
				return p
		if raise_on_miss:
			raise TaggedParameterNotFound()
		else:
			return None

	def add(self, param: TaggedParameter):
		self._params.append(param)

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "TaggedParameters":
		params = TaggedParameters()
		try:
			while True:
				number = buf.read_byte()
				length = buf.read_byte()
				data = buf.read(length)
				params.add(
					TaggedParameterMap.get(number, TaggedParameter)
					(number, length, data)
				)
		except EndOfBufferError:
			pass
		except Exception as e:
			logger.exception(e)
		finally:
			return params

	def write_to_buffer(self, buf: Buffer):
		for p in self._params:
			buf.write(bytes(p))

