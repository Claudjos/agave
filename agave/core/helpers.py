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


class BaseService:

	__slots__ = ()

	def process(self, data: bytes, address: SocketAddress) -> Any:
		raise NotImplementedError()

	def loop(self) -> bool:
		raise NotImplementedError()

	def set_finished(self):
		raise NotImplementedError()

	def stop(self):
		raise NotImplementedError()

	def run(self):
		raise NotImplementedError()


class Service(BaseService):

	__slots__ = ("wait", "interval", "max_read", "_repeat", "running", "sock")

	def __init__(self, wait: float = 1, interval: float = 1, max_read: int = None):
		self.wait = wait
		self.interval = interval
		self.max_read = max_read if max_read is not None else SOCKET_MAX_READ
		self._repeat = True

	def set_finished(self):
		self.running = False

	def stop(self):
		self.running = False

	def run(self):
		# Initialize
		self.running = True
		next_execution = time.time() + self.interval
		timeout = self.interval
		deadline = False
		# Run
		while self.running:
			# Waits for data
			rl, wl, xl = select.select([self.sock], [], [], timeout)
			# Process
			if rl != []:
				message = self.sock.recvfrom(self.max_read)
				result = self.process(*message)
				if result is not None:
					yield result
			# Loop
			if self._repeat and time.time() >= next_execution:
				if not self.loop():
					self._repeat = False
					deadline = time.time() + self.wait
					timeout = self.wait
				else:
					next_execution = time.time() + self.interval
			# Deadline
			if deadline is not False and time.time() >= deadline:
				self.running = False
		# StopIteration
		return

	