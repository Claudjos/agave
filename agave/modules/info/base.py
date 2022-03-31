from typing import Union


class MACAddress:

	__slots__ = ["address"]

	def __init__(self, address: Union[bytes, str]):
		if type(address) == str:
			self.address = self.str_to_mac(address)
		else:
			self.address = address

	@classmethod
	def str_to_mac(cls, address: str):
		return bytes(map(lambda x: int(x, 16), address.split(":")))

	@classmethod
	def mac_to_str(cls, address: str):
		return ':'.join('%02x'%i for i in address)

	def __str__(self):
		return self.mac_to_str(self.address)
