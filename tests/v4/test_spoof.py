import unittest
from tests.dummy import DummyInterface
from agave.core.arp import *
from agave.core.buffer import Buffer
from agave.core.ethernet import MACAddress
from agave.arp.resolve import Resolver
from ipaddress import IPv4Network, IPv4Address 


class TestARPSpoof(unittest.TestCase):

	REQUEST = ARP.who_has(
		IPv4Address("192.168.1.2"),
		MACAddress("00:1c:f2:be:4d:14"),
		IPv4Address("192.168.1.1")
	)

