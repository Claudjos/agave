import socket, time
from typing import Tuple
from agave.frames import ethernet, arp
from agave.frames.ethernet import MACAddress
from ipaddress import ip_address, ip_network, IPv4Address
from .utils import _create_socket, _parse, SOCKET_MAX_READ, ARPReaderLoop


HOST = Tuple[MACAddress, IPv4Address]


class Listener(ARPReaderLoop):
	"""This is a framework for a service collecting information about the hosts
	in a network, and how they interact with each other, by listening ARP messages. 
	It builds a sort of graph where the nodes correspond to the hosts, and the links
	represent a communication attempt (ARP request) between two hosts. Links are
	directed, from the sender to the target, and they can be hanging (the target
	node might not exists).
	Special events such as the discovery of new hosts or links, hardware address
	conflicts, or gratuitous ARP reply, trigger the invocation of callbacks, that
	are methods of this class whose implementation is delegated to sub classes.
	"""

	def on_node_discovery(self, host: HOST):
		"""This method is invoked when a new host is discovered."""
		pass

	def on_link_discovery(self, sender: HOST, target: HOST):
		"""This method is invoked when a host tries to resolve another host
		address for the first time."""
		pass

	def on_mac_change(self, ip: IPv4Address, old_mac: MACAddress, new_mac: MACAddress):
		"""This method is invoked when the hardware address associated to certain
		IP address changes."""
		pass

	def on_gratuitous_reply(self, sender: HOST, target: HOST):
		"""This method is invoked when a reply is received without being
		preceded by a request."""
		pass

	def __init__(
		self,
		sock: "socket.socket" = None,
		fresh_threshold: float = 0.5
	):
		if sock is None:
			sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		super().__init__(sock=sock)
		# used for storage
		self._nodes : dict = {}
		self._links : dict = {}
		# parameters
		self.fresh_threshold : float = fresh_threshold

	def _hash_link(self, sender: HOST, target: HOST) -> str:
		return str(sender[1]) + str(target[1])

	def _create_link(self, sender: HOST, target: HOST):
		_hash = self._hash_link(sender, target)
		self._links[_hash] = {"sender": sender, "target": target, "ts": time.time()}
		# callback
		self.on_link_discovery(sender, target)

	def _update_link(self, sender: HOST, target: HOST):
		_hash = self._hash_link(sender, target)
		self._links[_hash]["ts"] = time.time()

	def _search_link(self, sender: HOST, target: HOST) -> bool:
		_hash = self._hash_link(sender, target)
		return _hash in self._links

	def _hash_node(self, node: HOST) -> str:
		return str(node[1])

	def _create_node(self, node: HOST):
		_hash = self._hash_node(node)
		self._nodes[_hash] = {"ip": node[1], "mac": node[0], "ts": time.time()}
		# callback
		self.on_node_discovery(node)

	def _update_node(self, node: HOST):
		_hash = self._hash_node(node)
		if self._nodes[_hash]["mac"] != node[0]:
			old = self._nodes[_hash]["mac"]
			self._nodes[_hash]["mac"] = node[0]
			self._nodes[_hash]["ts"] = time.time()
			# callback
			self.on_mac_change(node[1], old, node[0])

	def _search_node(self, node: HOST) -> bool:
		_hash = self._hash_node(node)
		return _hash in self._nodes

	def process_request(self, sender: HOST, target: HOST):
		"""Saves a ARP request information.

		Note:
			The information saved are the sender addresses,
			and the attempt to communicate with the target.

		Args:
			sender: the sender hardware and protocol address.
			target: the target hardware and protocol address.

		"""
		# Creates/Update sender info
		if not self._search_node(sender):
			self._create_node(sender)
		else:
			self._update_node(sender)
		# Register the new [attempted] communication
		if not self._search_link(sender, target):
			self._create_link(sender, target)
		else:
			self._update_link(sender, target)

	def process_reply(self, sender: HOST, target: HOST):
		"""Saves a ARP reply information. Unrequested reply are discarded.
		
		Note:
			Only sender infos are saved, as the target infos, and the communication
			info, get saved by process_request (always called in case of valid
			replies).

		Args:
			sender: the sender hardware and protocol address.
			target: the target hardware and protocol address.

		"""
		legit = True
		# Check if legit
		try:
			"""If a reply is legit, it must be preceded by a request,
			thus a "fresh" link should exists.
			"""
			_hash = self._hash_link(target, sender)
			last_request_ts = self._links[_hash]["ts"]
			if (time.time() - last_request_ts) > self.fresh_threshold:
				legit = False
		except KeyError:
			legit = False
		# Exit if not legit
		if not legit:
			self.on_gratuitous_reply(sender, target)
			return
		# Creates/Update sender info
		if not self._search_node(sender):
			self._create_node(sender)
		else:
			self._update_node(sender)

	def process(self, address: Tuple, eth: ethernet.Ethernet, frame: arp.ARP):
		"""Process incoming/outgoing ARP frames."""
		sender = (
			MACAddress(frame.sender_hardware_address),
			IPv4Address(frame.sender_protocol_address)
		)
		target = (
			MACAddress(frame.target_hardware_address),
			IPv4Address(frame.target_protocol_address)
		)
		if frame.operation == arp.OPERATION_REPLY:
			self.process_reply(sender, target)
		if frame.operation == arp.OPERATION_REQUEST:
			self.process_request(sender, target)
