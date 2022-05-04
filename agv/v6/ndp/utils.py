import socket, struct


def create_ndp_socket() -> "socket.socket":
	return socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)


def join_group(sock: "socket.socket", address: str):
	"""Joins a multicast group. Necessary to receive multicast message on a socket at
	network layer.

	Args:
		sock: socket.
		address: multicast address.

	"""
	mreq = struct.pack(
		"16s15s".encode('utf-8'),
		socket.inet_pton(socket.AF_INET6, address),
		(chr(0) * 16).encode('utf-8')
	)
	sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

