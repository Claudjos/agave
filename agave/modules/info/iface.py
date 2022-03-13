import socket
import fcntl
import struct


def get_addresses(s, ifname: str):
	 
		iface = struct.pack('256s', bytes(ifname, 'utf-8')[:15])
		

		eth = fcntl.ioctl(s.fileno(), 0x8927, iface)[18:24]
		eth2 = ":".join('%02x' % b for b in eth)

		try:
			ip = fcntl.ioctl(s.fileno(), 0x8915, iface)[20:24]
			ip2 = socket.inet_ntoa(ip)
		except:
			ip = ip2 = None

		return {
			"eth": eth,
			"formatted_eth": eth2,
			"ip": ip,
			"formatted_ip": ip2
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
	print("{:20}\t{}\t{:20}\t{}\t".format("NAME", "ID", "ETHER ADDR", "IP ADDR"))
	print("---------------------------------------------------------------------")
	for iface in interfaces():
		print("{:20}\t{}\t{}\t{}\t".format(
			iface.get("name"),
			iface.get("id"),
			iface.get("formatted_eth"),
			iface.get("formatted_ip", "")
		))
