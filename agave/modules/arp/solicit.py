from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import ip_address, ip_network, IPv4Address
import socket
import time


def who_is_at(
	sender_mac: bytes, sender_ipv4: IPv4Address,
	broadcast: bytes, target_ipv4: IPv4Address
) -> bytes:
	eth_frame = ethernet.Ethernet(broadcast, sender_mac, ethernet.ETHER_TYPE_ARP)
	arp_frame = arp.ARP.build(
		arp.OPERATION_REQUEST,
		sender_mac, sender_ipv4.packed,
		broadcast, target_ipv4.packed
	)
	buf = Buffer.from_bytes()
	eth_frame.write_to_buffer(buf)
	arp_frame.write_to_buffer(buf)
	return bytes(buf)


def hosts(subnet, me: IPv4Address):
	for address in ip_network(subnet).hosts():
		if address != me:
			yield address
	return


def all_packet(subnet, sender_mac, sender_ipv4, broadcast, repeat=1):
	for _ in range(0, repeat):
		for address in hosts(subnet, sender_ipv4):
			yield who_is_at(sender_mac, sender_ipv4, broadcast, address)
	return


def main(argv):
	if len(argv) < 4:
		print("Too few parameters")
	else:
		_main(argv[0], argv[1], argv[2], argv[3])


def _main(iface: str, subnet: str, ipv4: str, mac: str):
	interface = (iface, 1)
	sender_mac = ethernet.str_to_mac(mac)
	sender_ipv4 = ip_address(ipv4)
	broadcast = b'\xff\xff\xff\xff\xff\xff'
	rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	print("Sending ARP requests...")
	for data in all_packet(subnet, sender_mac, sender_ipv4, broadcast, repeat=3):
		rawsocket.sendto(data, interface)
		time.sleep(0.01)
