from .core import Frame


HARDWARE_TYPE_ETHERNET = 0x0001
PROTOCOL_TYPE_IP = 0x0800

OPERATION_REQUEST = 1
OPERATION_REPLY = 2


class ARP(Frame):

	def __init__(
		self,
		hardware_type: int, protocol_type: int,
		hardware_addr_len: int, protocol_addr_len: int,
		operation: int,
		sender_hardware_address: bytes, sender_protocol_address: bytes,
		target_hardware_address: bytes, target_protocol_address: bytes
	):
		self.hardware_type = hardware_type
		self.protocol_type = protocol_type
		self.hardware_addr_len = hardware_addr_len
		self.protocol_addr_len = protocol_addr_len
		self.operation = operation
		self.sender_hardware_address = sender_hardware_address
		self.sender_protocol_address = sender_protocol_address
		self.target_hardware_address = target_hardware_address
		self.target_protocol_address = target_protocol_address

	@classmethod
	def read_from_buffer(cls, buf):
		hardware_type = buf.read_short()
		protocol_type = buf.read_short()
		hardware_addr_len = buf.read_byte()
		protocol_addr_len = buf.read_byte()
		operation = buf.read_short()
		sender_hardware_address = buf.read(hardware_addr_len)
		sender_protocol_address = buf.read(protocol_addr_len)
		target_hardware_address = buf.read(hardware_addr_len)
		target_protocol_address = buf.read(protocol_addr_len)
		return cls(
			hardware_type, protocol_type,
			hardware_addr_len, protocol_addr_len,
			operation,
			sender_hardware_address, sender_protocol_address,
			target_hardware_address, target_protocol_address
		)

	def write_to_buffer(self, buf):
		buf.write_short(self.hardware_type)
		buf.write_short(self.protocol_type)
		buf.write_byte(self.hardware_addr_len)
		buf.write_byte(self.protocol_addr_len)
		buf.write_short(self.operation)
		buf.write(self.sender_hardware_address)
		buf.write(self.sender_protocol_address)
		buf.write(self.target_hardware_address)
		buf.write(self.target_protocol_address)

	@classmethod
	def build(
		cls,
		operation: int,
		sender_hardware_address: bytes, sender_protocol_address: bytes,
		target_hardware_address: bytes, target_protocol_address: bytes
	):
		"""
		Build a frame assuming hardware and protocol to be Ethernet and IPv4.
		"""
		return cls(
			HARDWARE_TYPE_ETHERNET, PROTOCOL_TYPE_IP, 6, 4,
			operation,
			sender_hardware_address, sender_protocol_address,
			target_hardware_address, target_protocol_address
		)
