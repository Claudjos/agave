"""Utilities to handle IRDP package at link layer rather the network.

"""
import socket, struct


def create_irdp_socket() -> "socket.socket":
	return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)


def join_group(sock: "socket.socket", address: str):
	"""Joins a multicast group. Necessary to receive multicast message on a socket at
	network layer.

	Args:
		sock: socket.
		address: multicast address.

	"""
	mreq = socket.inet_pton(socket.AF_INET, address) + struct.pack('=I', socket.INADDR_ANY)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

