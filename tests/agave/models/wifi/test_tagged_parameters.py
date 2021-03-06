import unittest
from agave.models.wifi.tags import (
	TaggedParameters, 
	PARAM_SSID_PARAMETER_SET, SSID,
	PARAM_RSN_INFORMATION, 
	PARAM_SUPPORTED_RATES, SupportedRates,
	PARAM_DS_PARAMETER_SET, DSParameterSet
)


class TestTaggedParameter(unittest.TestCase):

	message = (
		b'\x00\x0b\x53\x61\x6e\x74\x6f\x72\x6f\x57\x69\x66\x69\x01\x08\x82'
		b'\x84\x8b\x96\x12\x24\x48\x6c\x03\x01\x0b\x32\x04\x0c\x18\x30\x60'
		b'\x33\x08\x20\x01\x02\x03\x04\x05\x06\x07\x33\x08\x21\x05\x06\x07'
		b'\x08\x09\x0a\x0b\xdd\x27\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10'
		b'\x44\x00\x01\x02\x10\x47\x00\x10\x28\x80\x28\x80\x28\x80\x18\x80'
		b'\xa8\x80\x00\x0c\xf6\xbe\x4d\x04\x10\x3c\x00\x01\x01\x05\x04\x00'
		b'\x01\x00\x10\x2a\x01\x00\x2d\x1a\xee\x11\x17\xff\xff\x00\x00\x01'
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00'
		b'\x00\x00\x3d\x16\x0b\x07\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x01\x01\x30\x14\x01'
		b'\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac'
		b'\x02\x00\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x00'
		b'\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\x0b\x05\x02'
		b'\x00\x1b\x12\x7a\xdd\x1e\x00\x90\x4c\x33\xee\x11\x17\xff\xff\x00'
		b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00'
		b'\x00\x00\x00\x00\xdd\x1a\x00\x90\x4c\x34\x0b\x07\x06\x00\x00\x00'
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		b'\xdd\x07\x00\x0c\x43\x07\x00\x00\x00'
	)

	def test_read_ssid(self):
		"""Tests SSID Information."""
		params = TaggedParameters.from_bytes(self.message)
		ssid = params.get(PARAM_SSID_PARAMETER_SET)
		self.assertEqual(ssid.SSID, "SantoroWifi")

	def test_write_ssid(self):
		"""Tests SSID Information."""
		self.assertEqual(bytes(SSID.build("SantoroWifi")), 
			b'\x00\x0b\x53\x61\x6e\x74\x6f\x72\x6f\x57\x69\x66\x69')

	def test_read_supported_rates(self):
		"""Tests supported rates."""
		params = TaggedParameters.from_bytes(self.message)
		rates = params.get(PARAM_SUPPORTED_RATES)
		self.assertEqual(rates.rates, [0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c])

	def test_write_supported_rates(self):
		"""Tests supported rates."""
		self.assertEqual(bytes(SupportedRates.build([0x82, 0x84])), b'\x01\x02\x82\x84')

	def test_rsn(self):
		"""Tests RSN."""
		params = TaggedParameters.from_bytes(self.message)
		rsn = params.get(PARAM_RSN_INFORMATION)
		self.assertEqual(rsn.version, 1)
		self.assertEqual(rsn.group_cipher_suite_OUI, b'\x00\x0f\xac')
		self.assertEqual(rsn.group_cipher_suite_type, 4)
		self.assertEqual(rsn.pairwise_cipher_suit_count, 1)
		self.assertEqual(rsn.get_pairwise_cipher_suit_list(), [(b'\x00\x0f\xac', 4)])
		self.assertEqual(rsn.auth_key_management_count, 1)
		self.assertEqual(rsn.get_auth_key_management_list(), [(b'\x00\x0f\xac', 2)])
		self.assertEqual(rsn.capabilities, 0)

	def test_generic_read(self):
		"""Tests parsing."""
		params = TaggedParameters.from_bytes(self.message)
		channel = params.get(PARAM_DS_PARAMETER_SET).channel
		self.assertEqual(channel, 11)

	def test_write_ds_parameter_set(self):
		"""Tests building/writing."""
		tag = DSParameterSet.build(11)
		self.assertEqual(bytes(tag), b'\x03\x01\x0b')

