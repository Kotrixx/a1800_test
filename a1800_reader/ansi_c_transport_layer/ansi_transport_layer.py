import time

from a1800_reader.ansi_c_transport_layer.data_utils import calc_crc, conv_raw_to_list
from a1800_reader.phy_layer.network import NetAdapter


class ANSITransport:
	def __init__(self, meter_address, meter_ip, meter_port):
		self.meter_address = meter_address
		self.meter_ip = meter_ip
		self.meter_port = meter_port

		self.last_toggle_sent = 1
		self.last_toggle_received = 0

		self.last_packet = True

		self.net = NetAdapter(self.meter_ip,self.meter_port)

	def open(self) -> bool:
		"""
		Opens physical connection to meter, currently only a socket connection
		:return: True if connection is opened successfully, False otherwise
		"""
		self.net.sock = self.net.create_socket()
		if self.net.sock is not False:
			self.net.set_timeout(timeout=self.net.timeout)
			return True
		else:
			return False

	def close(self):
		"""
		Closes physical connection to meter, currently only a socket connection
		:return: None
		"""
		self.net.close_connection()

	def create_packet(self, data: list[int]) -> list[int]:
		"""
		Generates ANSI packet from data
		:param data: list of integers representing the data to send
		:return: list of integers representing the ANSI packet
		"""
		stp = 0xee
		ident = self.meter_address
		length = [len(data) >> 8, len(data) & 0xFF]

		if len(data) < 64:
			seq_nbr = 0x00
			ctrl = self.generate_control_byte(multipacket=0, first_packet=0)

			packet = [stp] + [ident] + [ctrl] + [seq_nbr]

			packet.extend(length)
			packet.extend(data)

			crc = calc_crc(packet)

			packet.extend(crc)

			return packet

	def generate_control_byte(self, multipacket: int = 0, first_packet: int = 0) -> int:
		"""
		Calculates control byte for ANSI packet
		:param multipacket: 1 if multipacket, 0 otherwise
		:param first_packet: 1 if first packet, 0 otherwise
		:return: control byte
		"""
		toggle_bit = self.last_toggle_sent ^ 1
		self.last_toggle_sent = toggle_bit

		control_byte = (multipacket << 7) | (first_packet << 6) | (toggle_bit << 5) | 0x00

		return control_byte

	def send_packet(self, packet: list[int]) -> bool:
		"""
		Send ANSI packet to meter over the physical connection
		:param packet: ANSI packet to send
		:return: True if packet is sent successfully, False otherwise
		"""
		reply = self.net.send_cmd(packet)

		return reply

	def get_data(self) -> dict:
		"""
		Get meter response
		:return: dictionary containing the response data and metadata
		"""
		result = self.get_single_packet()
		if result['status'] == "success":
			if result['seq_num'] == 0:
				result['type'] = "single"
				return result
			data = {}
			key_base = result['seq_num']
			current_seq = result['seq_num']
			key = "block_" + str(key_base - current_seq)
			data[key] = result['data']
			while result['seq_num'] > 0:
				time.sleep(0.5)
				result = self.send_ack()
				time.sleep(0.5)
				result = self.get_single_packet()
				if result['status'] == 'error':
					result["seq_num"] = current_seq
					continue
				print(f"packet received, packet number: {result['seq_num']}")
				current_seq = result['seq_num']
				key = "block_" + str(key_base - current_seq)
				data[key] = result['data']

			# print("data: ", data)
			return {'status': "success", "type": "multi", "data": data, "response_code": 0, "size": key_base}

	def get_single_packet(self) -> dict:
		"""
		Gets a single packet of ANSI data from the meter
		:return: dictionary containing the response data and metadata
		"""
		raw_data = self.net.get_reply()
		data = conv_raw_to_list(raw_data)

		print(f"raw data: {data}")
		try:
			if data[0] != 6 and data[0] != 238:
				return {'status': 'error', 'message': 'got NACK'}

			if len(raw_data) == 1:
				raw_data = self.net.get_reply()
				data = conv_raw_to_list(raw_data)

			if data[1] == 238 or data[0] == 238:
				current_toggle = (data[3] & 0x20) >> 5
				self.last_toggle_received = current_toggle

				if data[4] == 0:
					self.last_packet = True
				else:
					self.last_packet = False

				if data[0] == 238:
					first = (data[2] & 0x80) >> 7
					multipacket = (data[2] & 0x40) >> 7 #changing from 0x80 because bit 6 is
														#the multipacket indicator
					seq_num = data[3]
					data_len = (data[4] << 8) + data[5]
				else:
					first = (data[3] & 0x80) >> 7
					multipacket = (data[3] & 0x40) >> 7  # changing from 0x80 because bit 6 is
					# the multipacket indicator
					seq_num = data[4]
					data_len = (data[5] << 8) + data[6]

				if data[0] == 238:
					payload = data[6 : 6 + (data_len)]
				else:
					payload = data[7: 7 + (data_len)]

				return {'status': 'success', 'data': payload, 'multipacket': multipacket, 'seq_num': seq_num}
			else:
				return {'status': 'error', 'message': 'malformed packet'}
		except Exception as e:
			# print "got some kind of error"
			return {'status': 'error', 'message': 'no response'}

	def send_ack(self) -> bool:
		"""
		Send ACK byte to meter
		:return: True if ACK is sent successfully, False otherwise
		"""
		result = self.net.send_cmd([0x06])
		return result

	def send_nack(self):
		"""
		Send NACK byte to meter
		:return: True if NACK is sent successfully, False otherwise
		"""
		result = self.net.send_cmd([0x15])
		return result

	def reset_settings(self):
		"""
		Reset operation settings
		:return: None
		"""
		self.last_toggle_sent = 1
		self.last_toggle_received = 0
		self.last_packet = True
