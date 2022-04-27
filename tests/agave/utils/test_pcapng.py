import unittest
from agave.utils.pcapng import StreamLoader, StreamDumper
from agave.models.pcapng import (
	LINKTYPE_ETHERNET, OPTION_TYPE_COMMENT, OPTION_TYPE_IF_NAME, OPTION_TYPE_IF_IPV4ADDR, 
	OPTION_TYPE_IF_IPV6ADDR, OPTION_TYPE_IF_MACADDR
)
from tests.dummy import DummyInterface


class TestStreamIO(unittest.TestCase):

	def test_dump_load(self):
		"""Simply dumps data and loads them back."""
		file = "/tmp/TestStreamIO.txt"
		message1 = b'\xaa\xbb\xcc'
		message2 = b'\x00\x11\x22'
		dummy_nic = DummyInterface(name="wlan0")
		# Dumps data
		with StreamDumper.from_file(file) as dumper:
			dumper.start_section()
			dumper.add_interface("eth0", linktype=LINKTYPE_ETHERNET, snaplen=1024)
			dumper.add_network_interface(dummy_nic, linktype=LINKTYPE_ETHERNET, snaplen=1024)
			dumper.dump(message1)
			dumper.edump(dummy_nic.name, message2, comment="Test!")
		# Loads data
		with StreamLoader.from_file(file) as loader:
			stream = loader.stream_section()
			# Reads packets
			pkg1_iface, pkg1_data = next(stream)
			pkg2_iface, pkg2_data = next(stream)
			# Checks data
			self.assertEqual(pkg1_data, message1)
			self.assertEqual(pkg2_data, message2)
			# Check interface id
			self.assertEqual(pkg1_iface, 0)
			self.assertEqual(pkg2_iface, 1)
			# Load options for interface 1
			data = {
				k: v for k,v in map(
					lambda x: (x.code, x.value),
					loader.get_interface_by_id(pkg2_iface).get_options(
						endianness=loader.get_section_byte_order()
					)
				)
			}
			# Check options for interface 1
			self.assertEqual(data[OPTION_TYPE_IF_NAME], dummy_nic.name)
			self.assertEqual(data[OPTION_TYPE_IF_MACADDR], dummy_nic.mac)
			self.assertEqual(data[OPTION_TYPE_IF_IPV6ADDR].network_address, dummy_nic.ipv6)
			self.assertEqual(data[OPTION_TYPE_IF_IPV4ADDR][0], dummy_nic.ip)
			self.assertEqual(data[OPTION_TYPE_IF_IPV4ADDR][1], dummy_nic.network.netmask)

