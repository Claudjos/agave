"""RatioTapHeader is added from devices to supply additional
information to user space applications.

Todo:
	* parse data fields.

"""
from agave.core.frame import Frame
from agave.core.buffer import Buffer


class RadioTapHeader(Frame):

	__slots__ = ("revision", "pad", "length", "data")

	@classmethod
	def read_from_buffer(cls, buf):
		frame = cls()
		frame.revision = buf.read_byte() 
		frame.pad = buf.read_byte()
		frame.length = int.from_bytes(buf.read(2), byteorder="little")
		frame.data = buf.read(frame.length - 4)
		return frame

