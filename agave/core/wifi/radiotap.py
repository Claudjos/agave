"""RatioTapHeader is added from devices to supply additional
information to user space applications, and from user space
application to tune some settings in the device.
Note that not all settings can be changed, for example, is not
possible to change the channel used by the device with this
header.

Note:
	A bunch of classes with only static attributes may seem
	pretty stupid, and maybe they are, but the idea here is
	to later add properties to this classes to ease building
	and parsing of the flags. Remember that goal is a very 
	easy to use module, not an efficient one.

Spec:
	http://www.radiotap.org/

Todo:
	* add properties to fields classes.

"""
from typing import List
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
FIELD_TX_FLAGS				= 0X00008000	# not shown by Wireshark
							# 0x00010000
FIELD_DATA_RETRIES			= 0X00020000	# not shown by Wireshark
FIELD_CHANNEL_PLUS			= 0X00040000
FIELD_MCS_INFORMATION		= 0X00080000
FIELD_A_MPDU_STATUS			= 0X00100000
FIELD_VHT_INFORMATION		= 0X00200000
FIELD_FRAME_TIMESTAMP		= 0X00400000
FIELD_HE_INFORMATION		= 0X00800000
FIELD_HE_MU_INFORMATION		= 0X01000000
							# 0x02000000
FIELD_0_LENGTH_PSDU			= 0X04000000
FIELD_L_SIG					= 0X08000000
FIELD_RESERVED				= 0X10000000
FIELD_RADIO_TAP_NS_NEXT		= 0X20000000
FIELD_VENDOR_NS_NEXT		= 0X40000000
FIELD_EXT					= 0X80000000


class RadioTapField(Frame):
	"""General structure for radio tap header fields."""
	__slots__ = ("data")

	FIELD_CODE = 0
	BYTEORDER = "little"
	LENGTH = 0
	ALIGN = None

	@classmethod
	def align(cls):
		if cls.LENGTH == 0:
			return 1
		return cls.ALIGN if cls.ALIGN is not None else cls.LENGTH

	@classmethod
	def read_from_buffer(cls, buf: Buffer) -> "RadioTapField":
		x = cls()
		x.data = buf.read(cls.LENGTH)
		return x

	def write_to_buffer(self, buf: Buffer):
		buf.write(self.data)


class ZeroLengthField(RadioTapField):
	"""If present, there's no PSDU, i.e., no 802.11 frame follow."""
	FIELD_CODE = FIELD_0_LENGTH_PSDU
	LENGTH = 1


class AMPDUStatus(RadioTapField):
	"""If present, the frame was received as part of an a-MPDU."""
	FIELD_CODE = FIELD_A_MPDU_STATUS
	LENGTH = 8
	ALIGN = 4


class DBMAntennaNoise(RadioTapField):
	"""RF noise power at the antenna. in decibels difference from 1mW. Unit: dBm."""
	FIELD_CODE = FIELD_DB_ANTENNA_NOISE
	LENGTH = 1


class DBMAntennaSignal(RadioTapField):
	"""RF signal power at the antenna, in decibels difference from 1mW. Unit: dBm."""
	FIELD_CODE = FIELD_DB_ANTENNA_SIGNAL
	LENGTH = 1


class Antenna(RadioTapField):
	"""Rx/Tx antenna index for this packet."""
	FIELD_CODE = FIELD_ANTENNA
	LENGTH = 1


class Channel(RadioTapField):
	"""Channel Freq 2, Channel flags 2"""
	FIELD_CODE = FIELD_CHANNEL
	LENGTH = 4
	ALIGN = 2


class FHSS(RadioTapField):
	"""The hop set and pattern for frequency-hopping radios."""
	FIELD_CODE = FIELD_FHSS
	LENGTH = 1


class Flags(RadioTapField):
	"""Properties of transmitted and received frames."""
	FIELD_CODE = FIELD_FLAGS
	LENGTH = 1


class HEMUInformation(RadioTapField):
	"""Data related to PPDUs of HE_MU type that wasn’t already captured in the regular HE field."""
	FIELD_CODE = FIELD_HE_MU_INFORMATION
	LENGTH = 2


class HEInformation(RadioTapField):
	"""The frame was received or transmitted using the HE PHY."""
	FIELD_CODE = FIELD_FHSS
	LENGTH = 2


class LSIG(RadioTapField):
	"""The content of the L-SIG."""
	FIELD_CODE = FIELD_L_SIG
	LENGTH = 2


class LockQuality(RadioTapField):
	"""Quality of Barker code lock."""
	FIELD_CODE = FIELD_LOCK_QUALITY
	LENGTH = 2


class MCSInformation(RadioTapField):
	"""Indicates the MCS rate index as in IEEE_802.11n-2009."""
	FIELD_CODE = FIELD_MCS_INFORMATION
	LENGTH = 3
	ALIGN = 1


class RXFlags(RadioTapField):
	"""Properties of received frames."""
	FIELD_CODE = FIELD_RX_FLAG
	LENGTH = 2


class Rate(RadioTapField):
	"""TX/RX data rate."""
	FIELD_CODE = FIELD_RATE
	LENGTH = 1


class TSFT(RadioTapField):
	"""Value in microseconds of the MAC’s 64-bit 802.11 Time Synchronization Function timer 
	when the first bit of the MPDU arrived at the MAC. For received frames only."""
	FIELD_CODE = FIELD_TSFT
	LENGTH = 8


class TXAttenuation(RadioTapField):
	"""Transmit power expressed as unit less distance from max power set at factory calibration."""
	FIELD_CODE = FIELD_TX_ATTENUATION
	LENGTH = 2


class VHTInformation(RadioTapField):
	"""?"""
	FIELD_CODE = FIELD_VHT_INFORMATION
	LENGTH = 11
	ALIGN = 2


class VendorNameSpace(RadioTapField):
	"""?"""
	FIELD_CODE = FIELD_VENDOR_NS_NEXT
	LENGTH = 6
	ALIGN = 2


class DBTXAttenuation(RadioTapField):
	"""Transmit power expressed as decibel distance from max power set at factory calibration."""
	FIELD_CODE = FIELD_DB_TX_ATTENUATION
	LENGTH = 2


class DBAntennaNoise(RadioTapField):
	"""RF noise power at the antenna, decibel difference from an arbitrary, fixed reference."""
	FIELD_CODE = FIELD_DB_ANTENNA_NOISE 
	LENGTH = 1


class DBAntennaSignal(RadioTapField):
	"""RF signal power at the antenna, decibel difference from an arbitrary, fixed reference."""
	FIELD_CODE = FIELD_DB_ANTENNA_SIGNAL
	LENGTH = 1


class DBmTXPower(RadioTapField):
	"""Transmit power expressed as dBm (decibels from a 1 milliwatt reference). This is the 
	absolute power level measured at the antenna port."""
	FIELD_CODE = FIELD_DBM_TX_POWER
	LENGTH = 1


class FrameTimestamp(RadioTapField):
	"""The timestamp itself, in the unit defined in the field itself."""
	FIELD_CODE = FIELD_FRAME_TIMESTAMP
	LENGTH = 8


class TXFlags(RadioTapField):
	"""Properties of transmitted frames."""
	FIELD_CODE = FIELD_TX_FLAGS
	LENGTH = 2


class DataRetries(RadioTapField):
	"""Number of data retries a transmitted frame used."""
	FIELD_CODE = FIELD_DATA_RETRIES
	LENGTH = 1


radio_tap_fields = [
	(FIELD_TSFT, TSFT),
	(FIELD_FLAGS, Flags),
	(FIELD_RATE, Rate),
	(FIELD_CHANNEL, Channel),
	(FIELD_FHSS, FHSS),
	(FIELD_DBM_ANTENNA_SIGNAL, DBMAntennaSignal),
	(FIELD_DBM_ANTENNA_NOISE, DBMAntennaNoise),
	(FIELD_LOCK_QUALITY, LockQuality),
	(FIELD_TX_ATTENUATION, TXAttenuation),
	(FIELD_DB_TX_ATTENUATION, DBTXAttenuation),
	(FIELD_DBM_TX_POWER, DBmTXPower),
	(FIELD_ANTENNA, Antenna),
	(FIELD_DB_ANTENNA_SIGNAL, DBAntennaSignal),
	(FIELD_DB_ANTENNA_NOISE, DBAntennaNoise),
	(FIELD_RX_FLAG, RXFlags),
	(FIELD_TX_FLAGS, TXFlags),					# Note: Wireshark doesn't show this
	# TODO Bit 16
	(FIELD_DATA_RETRIES, DataRetries),			# Note: Wireshark doesn't show this
	(FIELD_CHANNEL_PLUS, RadioTapField),		# TODO Bit 18
	(FIELD_MCS_INFORMATION, MCSInformation),
	(FIELD_A_MPDU_STATUS, AMPDUStatus),
	(FIELD_VHT_INFORMATION, VHTInformation),
	(FIELD_FRAME_TIMESTAMP, FrameTimestamp),
	(FIELD_HE_INFORMATION, HEInformation),
	(FIELD_HE_MU_INFORMATION, HEMUInformation),
	# TODO Bit 25
	(FIELD_0_LENGTH_PSDU, ZeroLengthField),
	(FIELD_L_SIG, LSIG),
	# Bit 28 is reserved
	(FIELD_RADIO_TAP_NS_NEXT, RadioTapField),	# TODO bit 29
	(FIELD_VENDOR_NS_NEXT, VendorNameSpace),
	# Bit 31 EXT 
]


class RadioTapHeader(Frame):

	BYTEORDER = "little"

	__slots__ = ("revision", "pad", "length", "bitmasks", "offset", "data")

	@classmethod
	def is_present(self, field: int) -> bool:
		"""Check if at least one bit mask as the bit set."""
		for bitmask in self.bitmasks:
			if bitmask & field > 0:
				return True
		return False

	@classmethod
	def read_from_buffer(cls, buf: Buffer, parse_fields: bool = True) -> "RadioTapHeader":
		"""Read from buffer the RadioTap header, without parsing the fields."""
		frame = cls()
		frame.revision = buf.read_byte() 
		frame.pad = buf.read_byte()
		frame.length = buf.read_short()
		frame.offset = 4
		frame.bitmasks = []
		while True:
			frame.offset += 4
			bitmask = buf.read_int()
			frame.bitmasks.append(bitmask)
			if not (bitmask & FIELD_EXT):
				break
		frame.fields = []
		frame.data = buf.read(frame.length - frame.offset)
		return frame

	def get_fields(self) -> List[RadioTapField]:
		"""Parses the present fields."""
		if self.fields is None:
			buf = Buffer.from_bytes(self.data, "little")
			# Reads fields for each bit mask
			offset = self.offset
			self.fields = []
			for bitmask in self.bitmasks:
				for field, klass in radio_tap_fields:
					if bitmask & field:
						# removes padding
						required_alignment = klass.align()
						t = required_alignment - (offset % required_alignment)
						pad = t if t != required_alignment else 0
						offset += pad
						buf.read(pad)
						# parse field
						offset += klass.LENGTH
						self.fields.append(klass.read_from_buffer(buf))
			# Check
			assert offset == self.length
		return self.fields

