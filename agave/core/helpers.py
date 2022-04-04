import select, time
from typing import Tuple, Iterator, List, Callable, Any


SocketAddress = Tuple
MessageRaw = Tuple[bytes, SocketAddress]


SOCKET_MAX_READ = 0xffff


def stream(sock: "socket.socket", max_read: int = None) -> Iterator[MessageRaw]:
	max_read = max_read if max_read is not None else SOCKET_MAX_READ
	while True:
		yield sock.recvfrom(max_read)


def flood(sock: "socket.socket", messages: List[MessageRaw]) -> Callable:
	def fn():
		for data, addr in messages:
			sock.sendto(data, addr)
		return True
	return fn


def execute(
	sock: "socket.socket",
	process: Callable[[MessageRaw], Any],
	repeat: Callable[[], bool] = False,
	interval: float = 1,
	wait: float = 1,
	max_read: int = None
) -> Iterator[Any]:
	"""  

	Args:
		sock: socket to read from.
		process: handler for incoming data; 'execute' yields any value
			different from None returned by the handler.
		repeat: handler to invoke in loop; if repeat returns False,
			the loop stops.
		interval: repeat interval for the execution of 'repeat'.
		wait: additional time to wait for data after 'repeat' returned
			False.
		max_read: maximum number of bytes to receive from the socket at
			once. Default to helpers.MAX_SIZE.

	Yields:
		Any not None value returned by 'process'.

	"""
	max_read = max_read if max_read is not None else SOCKET_MAX_READ
	next_execution = time.time() + interval
	timeout = interval
	deadline = False
	while True:
		# Waits for data
		rl, wl, xl = select.select([sock], [], [], timeout)
		# process incoming data
		if rl != []:
			message = sock.recvfrom(max_read)
			result = process(message)
			if result is not None:
				yield result
		# call the repeat
		if repeat is not False:
			if time.time() >= next_execution:
				if not repeat():
					repeat = False
					deadline = time.time() + wait
					timeout = wait
				else:
					next_execution = time.time() + interval
		# exits
		if deadline is not False and time.time() >= deadline:
			break
	return

