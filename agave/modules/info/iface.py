from .interfaces import get_interfaces, get_interface_by_name


def main(args):
	if len(args) > 0:
		try:
			nic = get_interface_by_name(args[0])
		except NetworkInterfaceNotFound:
			print("Interfaces not found")
		else:
			print("{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}".format(
				"NAME", nic.name,
				"MAC", nic.mac,
				"IP", nic.ip,
				"NETWORK", nic.network,
				"BROADCAST", nic.broadcast
			))
	else:
		print("{:20}\t{:20}\t{:20}\t{:20}\t".format("NAME", "MAC", "IP", "NETWORK"))
		print("".join(["-"] * 88))
		nics = get_interfaces()
		for i in range(0, len(nics)):
			nic = nics[i]
			print("{:20}\t{:20}\t{:20}\t{:20}\t".format(
				nic.name, str(nic.mac), str(nic.ip), str(nic.network)
			))
