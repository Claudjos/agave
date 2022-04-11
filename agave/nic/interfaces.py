"""This module contains functions to retrieve information
about network interfaces on the system using ioctl.

Note:
    The attributes with name starting with SIOCGIF are 
    constants found in <bits/ioctls.h>.

"""
import socket, fcntl, struct
from typing import List, Union, Dict, Tuple
from ipaddress import ip_address, ip_network
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from agave.core.ethernet import MACAddress


IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


SIOCGIFADDR = 0x8915        # get PA address
SIOCGIFBRDADDR = 0x8919     # get broadcast PA address
SIOCGIFNETMASK = 0x891b     # get network PA mask
SIOCGIFHWADDR = 0x8927      # get HW address
SIOGIFINDEX = 0x8933        # get index


def _get_socket() -> socket.socket:
    """Creates a socket.

    Note:
        This is a utility meant to generate a socket with the only
        purpose to get a file number to use for ioctl calls.

    Returns:
        A IPv4/UDP socket.

    """
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class NetworkInterfaceNotFound(Exception):
    """Exception raised when a network interfaces is not found.

    """
    pass


class NetworkInterface:
    """This class represents a network interface and provides builders.

    Attributes:
        index: the interface index.
        name: the interface name.
        mac: the interface hardware address.
        ip: the interface network address.
        network: the network this device is connected to.
        broadcast: the broadcast address for the network.

    """

    __slots__ = ("index", "name", "mac", "ip", "network", "broadcast","ipv6", "netv6")

    def __init__(self, index: int, name: str, mac: MACAddress, ip: IPv4Address,  network: IPv6Network,
        broadcast: IPv4Address, ipv6: IPv6Address, net6: IPv6Network):
        self.index: int = index
        self.name: str = name
        self.mac: MACAddress = mac
        self.ip: IPv4Address = ip
        self.network: IPv6Network = network
        self.broadcast: IPAddress = broadcast
        self.ipv6: IPv6Address = ipv6
        self.netv6: IPv6Network = net6

    def __str__(self) -> str:
        return self.name

    @classmethod
    def get_by_name(cls, nic_name: str) -> "NetworkInterface":
        """Finds a network interfaces by name.
        
        Args:
            nic_name: the interface name.

        Returns:
            A network interface.

        Raises:
            NetworkInterfaceNotFound: if a network interfaces with
              this name is not found.

        """
        ipv6_info = cls._parse_ipv6_information()
        with _get_socket() as s:
            return cls.get_by_name_fileno(nic_name, s.fileno(), ipv6_info)

    @classmethod
    def get_by_name_fileno(cls, nic_name: str, fileno: int, ipv6_info: dict) -> "NetworkInterface":
        """Finds a network interfaces by name.

        Note:
            In contrast to get_by_name, this method allows the caller
            to pass a file number in order to use an existing socket for the
            ioctl calls.

        Args:
            nic_name: the interface name.
            fileno: the file number of a socket.

        Returns:
            A network interface.

        Raises:
            NetworkInterfaceNotFound: if a network interfaces with
              this name is not found.

        """
        try:
            iface = struct.pack('256s', bytes(nic_name, 'utf-8')[:15])
            index = fcntl.ioctl(fileno, SIOGIFINDEX, iface)[16]
            mac = MACAddress(fcntl.ioctl(fileno, SIOCGIFHWADDR, iface)[18:24])
        except OSError:
            raise NetworkInterfaceNotFound(
                "No interfaces found named %s" % (nic_name)
            )
        else:
            if nic_name in ipv6_info:
                ipv6, net6 = ipv6_info[nic_name]
            else:
                ipv6, net6 = None, None
        try:
            ip = ip_address(fcntl.ioctl(fileno, SIOCGIFADDR, iface)[20:24])
            broadcast = ip_address(fcntl.ioctl(fileno, SIOCGIFBRDADDR, iface)[20:24])
            netmask = ip_address(fcntl.ioctl(fileno, SIOCGIFNETMASK, iface)[20:24])
            network_address = ip_address(int.from_bytes(netmask.packed, byteorder="big") & int.from_bytes(ip.packed, byteorder="big"))
            network = ip_network("{}/{}".format(
                network_address,
                netmask
            ))
        except:
            ip = broadcast = network = None
        return cls(index, nic_name, mac, ip, network, broadcast, ipv6, net6)

    @classmethod
    def list(cls) -> List["NetworkInterface"]:
        """Returns all the network interfaces available.
        
        Returns:
            A list of network interfaces.

        """
        interfaces = []
        ipv6_info = cls._parse_ipv6_information()
        with _get_socket() as s:
            fileno = s.fileno()
            for _, nic_name in socket.if_nameindex():
                interfaces.append(cls.get_by_name_fileno(nic_name, fileno, ipv6_info))
        return interfaces

    @classmethod
    def get_by_host(cls, host: Union[str, IPAddress]) -> "NetworkInterface":
        """Finds a network interface directly connected to a network
        including a given host address.

        Args:
            host: the host network address.

        Returns:
            A network interface.

        Raises:
            NetworkInterfaceNotFound: If such interface is not found.

        """
        if type(host) == str:
            host = ip_address(host)
        for interface in cls.list():
            if host.version == 4 and interface.network is not None and host in interface.network:
                return interface
            elif host.version == 6 and interface.netv6 is not None and host in interface.netv6:
                return interface
        raise NetworkInterfaceNotFound(
            "No interface found connected to a network including %s" % (host)
        )

    @classmethod
    def _parse_ipv6_information(cls) -> Dict[str, Tuple[IPv6Address, IPv6Network]]:
        """Parses IPv6 information from /proc/net/if_inet6.

        Note:

            00000000000000000000000000000001 01 80 10 80       lo
            (1)                              (2)(3)(4)(5)      (6)

            (1) IPv6 Address, (2) Device ID, (3) Network prefix
            (4) Scope, (5) Flags, (6) Name.

        Returns:
            A map device name -> address, network.

        """
        mask = 0xffffffffffffffffffffffffffffffff
        result = {}
        lines = open("/proc/net/if_inet6").readlines()
        for line in lines:
            t = line.rstrip().split(" ")
            addr = t[0]
            prefix = int(t[2], 16)
            name = t[-1]
            _addr = IPv6Address(":".join([addr[i-4:i] for i in range(4,34,4)]))
            _net_a = IPv6Address(_addr._ip & (mask << prefix))
            _net = IPv6Network("{}/{}".format(_net_a, prefix))
            result[name] = (_addr, _net)
        return result


if __name__ == "__main__":
    """
    Prints information about network interfaces.

    Usage:
        python3 -m agave.nic.interfaces [interface]
    
    Examples:
        python3 -m agave.nic.interfaces
        python3 -m agave.nic.interfaces eth0

    """
    import sys


    if len(sys.argv) > 1:
        try:
            nic = NetworkInterface.get_by_name(sys.argv[1])
        except NetworkInterfaceNotFound as e:
            print(e)
        else:
            print("{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}\n{:20}{}".format(
                "INDEX", nic.index,
                "NAME", nic.name,
                "MAC", nic.mac,
                "IP", nic.ip,
                "NETWORK", nic.network,
                "BROADCAST", nic.broadcast,
                "IPv6", nic.ipv6,
                "NETWORKv6", nic.netv6,
            ))
    else:
        print("{:5}\t{:20}\t{:20}\t{:20}\t{:20}\t{:20}\t{:30}\t{:20}".format(
            "INDEX", "NAME", "MAC", "IPv4", "NETWORKv4", "BROADCASTv4", "IPv6", "NETWORKv6"))
        print("".join(["-"] * 180))
        for nic in NetworkInterface.list():
            print("{:5}\t{:20}\t{:20}\t{:20}\t{:20}\t{:20}\t{:30}\t{:20}".format(
                nic.index, nic.name, str(nic.mac), str(nic.ip), str(nic.network), str(nic.broadcast),
                str(nic.ipv6), str(nic.netv6)
            ))

