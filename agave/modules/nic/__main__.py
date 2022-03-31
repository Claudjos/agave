import sys
from .interfaces import NetworkInterface, NetworkInterfaceNotFound


def main(args):
	if len(args) > 0:
		try:
			nic = NetworkInterface.get_by_name(args[0])
		except NetworkInterfaceNotFound as e:
			print(e)
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
		nics = NetworkInterface.list()
		for i in range(0, len(nics)):
			nic = nics[i]
			print("{:20}\t{:20}\t{:20}\t{:20}\t".format(
				nic.name, str(nic.mac), str(nic.ip), str(nic.network)
			))


if __name__ == "__main__":
	main(sys.argv[1:])
