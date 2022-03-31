"""This module contains functions to retrieve information
about network interfaces on the system using ioctl.

Note:
    The attributes with name starting with SIOCGIF are 
    constants found in <bits/ioctls.h>.

"""

import socket, fcntl, struct
from typing import List, Union
from ipaddress import ip_address, ip_network
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from agave.frames.ethernet import MACAddress


IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


SIOCGIFADDR = 0x8915        # get PA address
SIOCGIFBRDADDR = 0x8919     # get broadcast PA address
SIOCGIFNETMASK = 0x891b     # get network PA mask
SIOCGIFHWADDR = 0x8927      # get HW address


class NetworkInterfaceNotFound(Exception):
    """Exception raised when a network interfaces is not found.

    """
    pass


class NetworkInterface:

    __slots__ = ["name", "mac", "ip", "network", "broadcast"]

    def __init__(self, name: str, mac: MACAddress, ip: IPAddress, 
        network: IPNetwork, broadcast: IPAddress):
        self.name = name
        self.mac = mac
        self.ip = ip
        self.network = network
        self.broadcast = broadcast

    def __str__(self):
        return self.name


def _get_socket() -> socket.socket:
    """Creates a socket.

    Returns:
        A IPv4/UDP socket.

    """
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def get_interface_by_name(nic_name: str) -> NetworkInterface:
    """Finds a network interfaces by name.
    
    Args:
        nic_name: the interface name.

    Returns:
        A network interface.

    Raises:
        NetworkInterfaceNotFound: if a network interfaces with
          this name is not found.

    """
    with _get_socket() as s:
        return get_interface_by_name_fileno(nic_name, s.fileno())


def get_interface_by_name_fileno(nic_name: str, fileno: int) -> NetworkInterface:
    """Finds a network interfaces by name.

    Note:
        In contrast to get_interface_by_name, this method allows the caller
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

    Todo:
        * add support for IPv6 network.

    """
    try:
        iface = struct.pack('256s', bytes(nic_name, 'utf-8')[:15])
        mac = MACAddress(fcntl.ioctl(fileno, SIOCGIFHWADDR, iface)[18:24])
    except OSError:
        raise NetworkInterfaceNotFound(
            "No interfaces found named %s" % (nic_name)
        )
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
    return NetworkInterface(
        nic_name,
        mac,
        ip,
        network,
        broadcast
    )


def get_interfaces() -> List[NetworkInterface]:
    """Returns all the network interfaces available.
    
    Returns:
        A list of network interfaces.

    """
    interfaces = []
    with _get_socket() as s:
        fileno = s.fileno()
        for _, nic_name in socket.if_nameindex():
            interfaces.append(get_interface_by_name_fileno(nic_name, fileno))
    return interfaces


def get_interface_by_host(host: IPAddress) -> NetworkInterface:
    """Finds a network interface directly connected to a network
    including a given host address.

    Args:
        host: the host network address.

    Returns:
        A network interface.

    Raises:
        NetworkInterfaceNotFound: If such interface is not found.

    """
    for interface in get_interfaces():
        if host in interface.network:
            return interface
    raise NetworkInterfaceNotFound(
        "No interface found connected to a network including %s" % (host)
    )
