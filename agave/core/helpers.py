import select, time
from typing import Tuple, Iterator, List, Callable, Any


SocketAddress = Tuple
MessageRaw = Tuple[bytes, SocketAddress]


SOCKET_MAX_READ = 0xffff


def stream(sock: "socket.socket", max_read: int = None) -> Iterator[MessageRaw]:
	max_read = max_read if max_read is not None else SOCKET_MAX_READ
	while True:
		yield sock.recvfrom(max_read)


class BaseJob:
	"""Defines the interface for a job."""

	__slots__ = ()

	def stop(self):
		"""Allows users to stop the execution of the job."""
		raise NotImplementedError()

	def run(self):
		"""Executes a job."""
		raise NotImplementedError()


class Job(BaseJob):
	"""A BaseJob subclass to develop almost any feature of agave packages. 

	Almost any feature in agave package has the same behavior:
	(1) execute code following the reception of packet (e.g, replying back,
		storing information);
	(2) execute code in a loop with constant timeout (e.g., requesting data,
		sending spoofed packets).

	This class takes care of receiving data and timeouts in a single thread
	The subclasses only need to implement the abstract methods 'process' (1),
	and 'loop' (2), thus reducing the amount of code to write and test.

	Attributes:
		sock: the socket to use for I/O.
		max_read: maximum number of bytes to receive from the socket at
			once. Default to SOCKET_MAX_READ.
		interval: timeout between 'loop' executions.
		wait: additional time to wait for data after 'loop' ends.

	Note:
		The execution of 'loop' might delay, or be skipped, if 'process', 'loop',
		or the code using 'stream', perform long blocking operations.

	"""
	__slots__ = ("wait", "interval", "max_read", "_loop_enabled", "_running", "sock")

	def __init__(self, sock: "socket.socket", wait: float = 1, interval: float = 1, max_read: int = None):
		self.sock: "socket.socket" = sock
		self.wait: float = wait
		self.interval: float = interval
		self.max_read: int = max_read if max_read is not None else SOCKET_MAX_READ
		self.enable_loop()

	def process(self, data: bytes, address: SocketAddress) -> Any:
		"""Invoked for each packet received from the socket."""
		raise NotImplementedError()

	def loop(self) -> bool:
		"""Invoked when the timeout elapses."""
		raise NotImplementedError()

	def disable_loop(self):
		"""Disables the execution of 'loop'. The Job will run until finished."""
		self._loop_enabled = False

	def enable_loop(self):
		"""Enables the execution of 'loop'."""
		self._loop_enabled = True

	def set_finished(self):
		"""Stops the execution of the service. Meant to be used by subclasses."""
		self._running = False

	def stop(self):
		"""Stops the execution of the service."""
		self._running = False

	def stream(self) -> Iterator[Any]:
		"""Run the service (invoke 'process' and 'loop') streaming the results.

		Yields:
			Any non None value returned by 'process'.

		"""
		# Initialize
		self._running = True
		next_execution = time.time() + self.interval
		timeout = self.interval
		deadline = False
		# Run
		while self._running:
			# Waits for data
			rl, wl, xl = select.select([self.sock], [], [], timeout)
			# Process
			if rl != []:
				message = self.sock.recvfrom(self.max_read)
				result = self.process(*message)
				if result is not None:
					yield result
			# Loop
			if self._loop_enabled and time.time() >= next_execution:
				if not self.loop():
					self.disable_loop()
					deadline = time.time() + self.wait
					timeout = self.wait
				else:
					next_execution = time.time() + self.interval
			# Deadline
			if deadline is not False and time.time() >= deadline:
				self._running = False
		# StopIteration
		return

	def run(self):
		"""Run the service but do not return any value."""
		for _ in self.stream():
			pass

