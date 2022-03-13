import socket
import fcntl
import struct
from ipaddress import ip_address, ip_network

"""
From <bits/ioctls.h>
"""
SIOCGIFADDR = 0x8915 		# get PA address
SIOCGIFBRDADDR = 0x8919 	# get broadcast PA address
SIOCGIFNETMASK = 0x891b 	# get network PA mask
SIOCGIFHWADDR = 0x8927 		# get HW address


def get_addresses(s, ifname: str):
	 
		iface = struct.pack('256s', bytes(ifname, 'utf-8')[:15])

		eth = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, iface)[18:24]
		eth2 = ":".join('%02x' % b for b in eth)

		try:
			ip = fcntl.ioctl(s.fileno(), SIOCGIFADDR, iface)[20:24]
			ip2 = socket.inet_ntoa(ip)

			broadcast = socket.inet_ntoa(fcntl.ioctl(s.fileno(), SIOCGIFBRDADDR, iface)[20:24])
			netmask = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, iface)[20:24]
			
			network = ip_address(int.from_bytes(netmask, byteorder="big") & int.from_bytes(ip, byteorder="big"))

			n = ip_network("{}/{}".format(
				str(network),
				socket.inet_ntoa(netmask)
			)).prefixlen

			network = f"{network}/{n}"

		except:
			ip = ip2 = broadcast = network = None

		return {
			"eth": eth,
			"formatted_eth": eth2,
			"ip": ip,
			"formatted_ip": ip2,
			"broadcast": broadcast,
			"network": network
		}


def interfaces():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	for iface in socket.if_nameindex():
		try:
			data = get_addresses(s, iface[1])
			data["name"] = iface[1]
			data["id"] = iface[0]
		except BaseException as e:
			print(e)
		else:
			yield data
	return


def main(args):
	if len(args) > 0:
		e = list(filter(lambda x: x.get("name") == args[0], interfaces()))
		if len(e) < 1:
			print("Interfaces not found")
		else:
			for key, value in e[0].items():
				print("{:20}\t{}".format(key, value))
	else:
		print("{:20}\t{:20}\t{}\t".format("NAME", "ETHER ADDR", "IP ADDR"))
		print("---------------------------------------------------------------------")
		for iface in interfaces():
			print("{:20}\t{}\t{}\t".format(
				iface.get("name"),
				iface.get("formatted_eth"),
				iface.get("formatted_ip", "")
			))
