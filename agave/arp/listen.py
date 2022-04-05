"""Passive listening.

Note:
	This feature might be removed as it is too specific, and so outside
	the goals of this project.

"""
import socket, time
from typing import Tuple
from agave.core import arp
from agave.core.ethernet import MACAddress
from agave.core.helpers import Job, SocketAddress
from ipaddress import ip_address, ip_network, IPv4Address
from .utils import _create_socket, _parse, SOCKET_MAX_READ, Host


class Listener(Job):
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

	def on_node_discovery(self, host: Host):
		"""This method is invoked when a new host is discovered."""
		pass

	def on_link_discovery(self, sender: Host, target: Host):
		"""This method is invoked when a host tries to resolve another host
		address for the first time."""
		pass

	def on_mac_change(self, ip: IPv4Address, old_mac: MACAddress, new_mac: MACAddress):
		"""This method is invoked when the hardware address associated to certain
		IP address changes."""
		pass

	def on_gratuitous_reply(self, sender: Host, target: Host):
		"""This method is invoked when a reply is received without being
		preceded by a request."""
		pass

	def __init__(
		self,
		sock: "socket.socket",
		fresh_threshold: float = 0.5
	):
		super().__init__(sock=sock, interval=3600)
		# used for storage
		self._nodes : dict = {}
		self._links : dict = {}
		# parameters
		self.fresh_threshold : float = fresh_threshold
		self.disable_loop()

	def _hash_link(self, sender: Host, target: Host) -> str:
		return str(sender[1]) + str(target[1])

	def _create_link(self, sender: Host, target: Host):
		_hash = self._hash_link(sender, target)
		self._links[_hash] = {"sender": sender, "target": target, "ts": time.time()}
		# callback
		self.on_link_discovery(sender, target)

	def _update_link(self, sender: Host, target: Host):
		_hash = self._hash_link(sender, target)
		self._links[_hash]["ts"] = time.time()

	def _search_link(self, sender: Host, target: Host) -> bool:
		_hash = self._hash_link(sender, target)
		return _hash in self._links

	def _hash_node(self, node: Host) -> str:
		return str(node[1])

	def _create_node(self, node: Host):
		_hash = self._hash_node(node)
		self._nodes[_hash] = {"ip": node[1], "mac": node[0], "ts": time.time()}
		# callback
		self.on_node_discovery(node)

	def _update_node(self, node: Host):
		_hash = self._hash_node(node)
		if self._nodes[_hash]["mac"] != node[0]:
			old = self._nodes[_hash]["mac"]
			self._nodes[_hash]["mac"] = node[0]
			self._nodes[_hash]["ts"] = time.time()
			# callback
			self.on_mac_change(node[1], old, node[0])

	def _search_node(self, node: Host) -> bool:
		_hash = self._hash_node(node)
		return _hash in self._nodes

	def process_request(self, sender: Host, target: Host):
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

	def process_reply(self, sender: Host, target: Host):
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

	def process(self, data: bytes, address: SocketAddress):
		"""Process incoming/outgoing ARP frames."""
		if address[1] == 0x0806 or address[1] == 0x0608:
			eth, frame = _parse(data)
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


if __name__ == "__main__":
	"""
	Sniffs ARP messages to collect information about the network.

	Usage:
		python3 -m agave.arp.listen

	Example:
		python3 -m agave.arp.listen

	"""
	class MyListener(Listener):

		def on_node_discovery(self, host: Host):
			print("New host discovered {} {}".format(host[0], host[1]), flush=True)

		def on_link_discovery(self, sender: Host, target: Host):
			print("New communication discovered {} {}".format(sender[1], target[1]), flush=True)

		def on_mac_change(self, ip: IPv4Address, old_mac: MACAddress, new_mac: MACAddress):
			print("MAC addressed associated to {} changed from {} to {}".format(
				ip, old_mac, new_mac
			), flush=True)

		def on_gratuitous_reply(self, sender: Host, target: Host):
			print("A reply {} {} came without {} requesting it".format(
				sender[0], sender[1], target[1]
			), flush=True)


	try:
		print("Listening...")
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		job = MyListener(sock)
		job.run()
	except KeyboardInterrupt:
		pass

