"""RatioTapHeader is added from devices to supply additional
information to user space applications.

Spec:
	http://www.radiotap.org/

Todo:
	* parse data fields.

"""
from agave.core.frame import Frame
from agave.core.buffer import Buffer


FIELD_TSFT  				= 0X00000001
FIELD_FLAGS 				= 0X00000002
FIELD_RATE					= 0X00000004
FIELD_CHANNEL				= 0X00000008
FIELD_FHSS					= 0X00000010
FIELD_DBM_ANTENNA_SIGNAL	= 0X00000020
FIELD_DBM_ANTENNA_NOISE		= 0X00000040
FIELD_LOCK_QUALITY			= 0X00000080
FIELD_TX_ATTENUATION		= 0X00000100
FIELD_DB_TX_ATTENUATION		= 0X00000200
FIELD_DBM_TX_POWER			= 0X00000400
FIELD_ANTENNA				= 0X00000800
FIELD_DB_ANTENNA_SIGNAL		= 0X00001000
FIELD_DB_ANTENNA_NOISE		= 0X00002000
FIELD_RX_FLAG				= 0X00004000

FIELD_CHANNEL				= 0X00040000
FIELD_MCS_INFORMATION		= 0X00080000
FIELD_A_MPDU_STATUS			= 0X00100000
FIELD_VHT_INFORMATION		= 0X00200000
FIELD_FRAME_TIMESTAMP		= 0X00400000
FIELD_HE_INFORMATION		= 0X00800000
FIELD_HE_MU_INFORMATION		= 0X01000000

FIELD_0_LENGTH_PSDU			= 0X04000000 # If true, there's no PSDU, i.e., no 802.11 frame follow
FIELD_L_SIG					= 0X08000000
FIELD_RESERVED				= 0X10000000
FIELD_RADIO_TAP_NS_NEXT		= 0X20000000
FIELD_VENDOR_NS_NEXT		= 0X40000000
FIELD_EXT					= 0X80000000


class RadioTapHeader(Frame):

	BYTEORDER = "little"

	__slots__ = ("revision", "pad", "length", "present")

	def is_present(self, field: int) -> bool:
		return self.present & field > 0

	def set_present(self, field: int):
		self.present |= field

	def unset_present(self, field: int):
		self.present ^= self.present & field

	@classmethod
	def read_from_buffer(cls, buf: Buffer):
		frame = cls()
		begin = buf.tell()
		frame.revision = buf.read_byte() 
		frame.pad = buf.read_byte()
		frame.length = buf.read_short()
		frame.present = buf.read_int()
		# Parse fields
		# Moves the cursor at the end of the header
		buf.seek(begin + frame.length)
		return frame

