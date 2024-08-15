import socket
import sys


def pretty_string(data):
	new_str = ""
	for byte in data:
		new_str += hex(ord(byte)) + ' '

	return new_str


def serialize_cmd(cmd: list[int]) -> str | bytes:
	"""
	Converts a list of integers into a string of bytes to send via network
	:param cmd: list of integers to convert
	:return: if running on Python 2 returns a string, if running on Python 3 returns a bytes object
	"""
	result_str = ""
	if sys.version_info[0] < 3:
		for byte in cmd:
			result_str += chr(byte)
	else:
		try:
			values = bytes(cmd)
			result_str = values
		except Exception as e:
			print("exception: {}".format(e))

	return result_str


def get_bind_ip() -> str:
	"""
	Gets the IP address of the local machine
	:return: IP address of the local machine
	"""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	bind_ip = s.getsockname()[0]

	return str(bind_ip)


class NetAdapter:
	def __init__(self, ip, port, timeout=60.0):
		self.ip = ip
		self.port = port
		self.timeout = timeout
		self.bind_ip = get_bind_ip()
		self.sock = self.create_socket()
		if self.sock is not False:
			# print("setting timeout")
			self.set_timeout(timeout=timeout)

	def set_timeout(self, timeout: float):
		"""
		Sets timeout for socket
		:param timeout: value in seconds
		:return: None
		"""
		self.sock.settimeout(timeout)

	def create_socket(self):
		"""
		Creates a socket binding to the local IP address and specified port
		:return: socket object if created, None if creation fails
		"""
		try:
			# Create a TCP/IP socket
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.bind((self.bind_ip, 0))
			server_address = (self.ip, self.port)
			# print(sys.stderr, "connecting to %s port %s" % server_address)
			sock.connect(server_address)
			return sock
		except Exception as e:
			print("Exception: " + str(e))
			return False

	def get_reply(self, buffer_size: int = 1024) -> str | bytes:
		"""
		Gets reply from socket
		:param buffer_size: buffer size for the reception
		:return: reply from socket as a string if on Python 2, as a bytes object if on Python 3
		"""
		try:
			# Look for the response
			amount_received = 0
			reply = ""

			data = self.sock.recv(buffer_size)
			# print("data received")
			amount_received += len(data)
			if sys.version_info[0] < 3:
				reply += data
			else:
				reply = data
			return reply
		except Exception as e:
			print("Exception found: ", str(e))
			return ""

	def send_cmd(self, cmd: list[int], print_tx: bool = False) -> bool:
		"""
		Sends a command to the socket
		:param cmd: list of integers to send
		:param print_tx: if True prints the command to send
		:return: True if command is sent successfully, False otherwise
		"""
		cmd = serialize_cmd(cmd)
		try:
			# send data
			if print_tx:
				print(sys.stderr, 'Sending %s' % cmd)

			self.sock.send(cmd)
		except Exception as e:
			print("got exception in send cmd {}".format(e))
			return False

		return True

	def close_connection(self):
		"""
		Closes socket
		:return: None
		"""
		self.sock.close()
