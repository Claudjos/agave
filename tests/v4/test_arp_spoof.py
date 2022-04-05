import unittest
from tests.dummy import DummyInterface, DummySock
from agave.core.arp import ARP, OPERATION_REQUEST
from agave.core.buffer import Buffer
from agave.core.ethernet import MACAddress, ETHER_TYPE_ARP
from agave.arp.spoof import Spoofer
from agave.arp.utils import create_filter, _parse
from ipaddress import IPv4Network, IPv4Address 


class TestARPSpoof(unittest.TestCase):

	def test_spoof(self):
		"""Should reply back with poisoned data."""
		dummysocket = DummySock()
		dummyinterface = DummyInterface()
		job = Spoofer(
			dummysocket,
			dummyinterface.mac,
			create_filter(
				OPERATION_REQUEST,
				sender=IPv4Address("192.168.1.1"),
				target=IPv4Address("192.168.1.2")
			),
			[]
		)
		request = ARP.who_has(
			IPv4Address("192.168.1.2"),
			MACAddress("00:1c:f2:be:4d:14"),
			IPv4Address("192.168.1.1")
		)
		job.process(request, dummyinterface.get_socket_address(ETHER_TYPE_ARP))
		_, reply = _parse(dummysocket.get_message(0)[0])
		self.assertEqual(reply.sender_hardware_address, dummyinterface.mac.packed)
		self.assertEqual(reply.sender_protocol_address, IPv4Address("192.168.1.2").packed)
		self.assertEqual(reply.target_hardware_address, MACAddress("00:1c:f2:be:4d:14").packed)
		self.assertEqual(reply.target_protocol_address, IPv4Address("192.168.1.1").packed)

