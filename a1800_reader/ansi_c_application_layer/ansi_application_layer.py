import datetime
import math
import sys
import time

import pandas as pd
import pyDes

from a1800_reader.ansi_c_application_layer.data_operations import twos_comp, convert_num_to_twos_comp
from a1800_reader.ansi_c_transport_layer.ansi_transport_layer import ANSITransport
import pytz

peru_tz = pytz.timezone("America/Lima")
utc_tz = pytz.timezone("UTC")


class ANSIApplication:
	def __init__(self, meter_address, meter_ip, meter_port, password, password_level,
				 user, time_delay, logical_id):
		self.transport = ANSITransport(meter_address, meter_ip, meter_port)
		self.response_codes = ["ok", "error", "service not supported", "insufficient security clearance",
							   "operation not possible", "innapropriate action requested", "device busy",
							   "data not ready", "data locked", "renegotiate request", "invalid service sequence state"]

		self.password = password
		self.password_level = password_level

		self.key = self.password[:8]

		self.user_id = [0x00, 0x02]
		self.user = user

		self.logical_id = logical_id

		self.ni_fmat1 = 6  # using default values here for NI_FMAT1 and NI_FMAT2
		self.ni_fmat2 = 5

		self.time_delay = time_delay

		self.raw_present_values = []
		self.present_values = {}

		self.raw_current_data = []
		self.current_data = {}

		self.ticket = None

		self.scale = None

		self.nbr_present_demands = None
		self.nbr_present_values = None
		self.nbr_occur = None
		self.nbr_self_reads = None
		self.nbr_summations = None
		self.nbr_demands = None
		self.nbr_tiers = None
		self.nbr_coincident = None

		self.load_profile_data = list()
		self.instrumentation_data = list()

	@property
	def dimension_profile_payload(self):
		return [0x30, 0x00, 0x3c]

	@property
	def actual_dimension_profile_payload(self):
		return [0x30, 0x00, 0x3d]

	@property
	def profile_payload(self):
		return [0x3f, 0x00, 0x40, 0x00, 0x00, 0x00, 0x16, 0xe0]

	def open(self) -> bool:
		"""
		Open communication channel to meter
		:return: True if connection is opened successfully, False otherwise
		"""
		result = self.transport.open()
		return result

	def close(self):
		"""
		Closes communication channel to meter
		:return: None
		"""
		self.transport.close()

	def send_msg(self, payload: list[int]) -> dict:
		"""
		Send ANSI message to meter and get the response
		:param payload: ANSI message to send without formatting
		:return: dictionary containing the response data and metadata
		"""
		packet = self.transport.create_packet(payload)
		print("packet to send: {}".format([hex(num) for num in packet]))
		reply = self.transport.send_packet(packet)
		if reply:
			reply = self.transport.get_data()
			if (reply is not None) and ("status" in reply.keys()) and (reply['status'] == "success"):
				data = reply['data']
				if reply['type'] == "single":
					if data[0] == 0:
						return {'status': 'success', 'response_code': self.response_codes[data[0]], 'data': data}
					else:
						return {'status': 'error', 'response_code': self.response_codes[data[0]]}
				elif reply['type'] == "multi":
					return reply
			else:
				print(f"reply: {reply}")
				return {'status': 'failure'}
		else:
			print(f"reply: {reply}")
			return {"status": "failure"}

	def send_init(self) -> dict:
		"""
		Send initialization message to meter
		:return: dictionary containing the response data and metadata
		"""
		result = self.send_msg([0x20])
		if result['status'] == "success":
			self.ticket = result['data'][8:16]
			return {'status': 'success', 'response_code': result['response_code']}
		else:
			return result

	@property
	def encrypt_ticket(self) -> str | bytes:
		"""
		Encrypt the ticket using the password using ECB (Electronic Code Book) mode
		:return: encrypted ticket as string if running on Python 2, bytes if running on Python 3
		"""
		des = pyDes.des(self.key)
		print(self.ticket)
		ticket_str = ""
		if sys.version_info[0] < 3:
			for byte in self.ticket:
				ticket_str += chr(byte)
		else:
			ticket_str = bytes(self.ticket)
		result = des.encrypt(ticket_str)

		return result

	def send_negotiate(self, packet_size: list[int] = None, packet_num: int = 0xff) -> dict:
		"""
		Send negotiate message to meter
		:param packet_size: size of packets to send as a 16 bit value split in a list of two bytes
		:param packet_num: number of packets to send
		:return: dictionary containing the response data and metadata
		"""
		if packet_size is None:
			packet_size = [0x00, 0x80]
		full_payload = [0x60] + packet_size + [packet_num]
		result = self.transport.send_ack()

		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(full_payload)
			if result['status'] == "success":
				return {'status': 'success', 'response_code': result['response_code']}
			else:
				return result
		else:
			return {'status': 'error', 'response_code': 'network error'}

	def send_logon(self) -> dict:
		"""
		Send logon message to meter
		:return: dictionary containing the response data and metadata
		"""
		user_list = []
		for char in self.user:
			user_list.append(ord(char))

		payload = [0x50] + self.user_id + user_list

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			if result:
				result = self.send_msg(payload)
				if result['status'] == "success":
					return {'status': 'success', 'response_code': result['response_code']}
				else:
					return result
		else:
			return {'status': 'error', 'response_code': 'network error'}

	def send_authenticate(self) -> dict:
		"""
		Send encrypted password to meter for authentication
		:return: dictionary containing the response data and metadata
		"""
		encrypted_data = self.encrypt_ticket
		encrypted = []
		for byte in encrypted_data:
			if sys.version_info[0] < 3:
				encrypted.append(ord(byte))
			else:
				if type(byte) == int:
					encrypted.append(byte)
				else:
					encrypted.append(ord(byte))

		payload = [0x53, 0x09] + [self.password_level] + encrypted

		result = self.transport.send_ack()
		if result:
			result = self.send_msg(payload)
			if result['status'] == "success":
				return {'status': 'success', 'response_code': result['response_code']}
			else:
				return result
		else:
			return {'status': 'error', 'response_code': 'network error'}

	def read_table(self, payload: list[int]) -> dict:
		"""
		Read a table from the meter, specified in the payload.
		:param payload: payload of the read table message
		:return: dictionary containing the response data and metadata
		"""
		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			if result['status'] == "success":
				return {'status': 'success', 'response_code': result['response_code'], "data": result['data']}
			else:
				return result

	def read_instrumentation_scale_factor(self) -> dict:
		"""
		Read table containing the scale factor for the instrumentation data
		:return: dictionary containing the response data and metadata
		"""
		payload = [0x30, 0x08, 0x10]
		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			if result['status'] == "success":
				if result["data"][0] == 0:
					scale = result["data"][3]
					scale = twos_comp(scale, 8)
					self.scale = scale

				return {"status": 'success', "scale": self.scale}
			else:
				return result

	def read_actual_reg_table(self) -> dict:
		"""
		Read table containing the actual register data
		:return: dictionary containing the response data and metadata
		"""
		payload = [0x30, 0x00, 0x15]

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			if result['status'] == "success":
				if result["data"][0] == 0:
					self.nbr_present_demands = result["data"][11]
					self.nbr_present_values = result["data"][12]
					self.nbr_occur = result["data"][9]
					self.nbr_self_reads = result["data"][5]
					self.nbr_summations = result["data"][6]
					self.nbr_demands = result["data"][7]
					self.nbr_tiers = result["data"][10]
					self.nbr_coincident = result["data"][8]

				return {"status": 'success', "response_code": result['response_code'],
						"nbr_present_demands": self.nbr_present_demands,
						"nbr_present_values": self.nbr_present_values,
						"nbr_occur": self.nbr_occur,
						"nbr_self_reads": self.nbr_self_reads,
						"nbr_summations": self.nbr_summations,
						"nbr_demands": self.nbr_demands,
						"nbr_tiers": self.nbr_tiers,
						"nbr_coincident": self.nbr_coincident}
			else:
				return result

	def read_std_definition_table(self) -> dict:
		"""
		Read table containing the standard definition data
		:return: dictionary containing the response data and metadata
		"""
		payload = [0x30, 0x00, 0x10]

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)

		return result

	def read_abb_definition_table(self) -> dict:
		"""
		Read table containing the ABB definition data
		:return: dictionary containing the response data and metadata
		"""
		payload = [0x30, 0x08, 0x11]

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			data = []
			if result['type'] == "multi":
				for index in range(result['size'] + 1):
					try:
						data += result['data']["block_" + str(index)]
					except Exception as e:
						# print("exception: {}".format(e))
						break

			# print("got the whole data")

			return {"status": "success",
					"response_code": result['response_code'],
					"data": result['data']}

	def read_current_register_data_table(self) -> dict:
		"""
		Read table containing the current register data
		:return: dictionary containing the response data and metadata
		"""
		payload = [0x30, 0x00, 0x17]

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			data = []

			res = {}
			if result['type'] == "multi":
				for index in range(result['size'] + 1):
					try:
						data += result['data']["block_" + str(index)]
					except Exception as e:
						# print("exception: {}".format(e))
						break

				self.raw_current_data = data

	def read_present_reg_selection_table(self) -> dict:
		"""
		Read table containing the present register selection data
		:return: dictionary containing the response data and metadata
		"""
		payload = [0x30, 0x00, 0x1b]

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			return result

	def read_present_reg_data_table(self):
		"""
		Read table containing the present register data
		:return: None
		"""
		payload = [0x30, 0x00, 0x1c]

		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			if result['status'] == "success":
				data = []
				if result['type'] == "multi":
					for index in range(result['size'] + 1):
						try:
							data += result['data']["block_" + str(index)]

						# print("data: {}".format(data))
						except Exception as e:
							# print("exception: {}".format(e))
							break

				if len(data) > 0:
					self.raw_present_values = data

	def send_logoff(self) -> dict:
		"""
		Send logoff message to meter
		:return: dictionary containing the response data and metadata
		"""
		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg([0x52])
			if result['status'] == "success":
				return {'status': 'success', 'response_code': result['response_code']}
			else:
				return result

	def send_terminate(self) -> dict:
		"""
		Send terminate message to meter
		:return: dictionary containing the response data and metadata
		"""
		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg([0x21])
			if result['status'] == "success":
				return {'status': 'success', 'response_code': result['response_code']}
			else:
				return result

	def generate_current_values(self):
		"""
		Generate the current values from the raw data and store them in the current_data dictionary
		:return: None
		"""
		partial = self.raw_current_data[4:]

		index = 0
		while index < 4:
			value = (partial[index * 6 + 5] << 40) | (partial[index * 6 + 4] << 32) | (partial[index * 6 + 3] << 24) \
					| (partial[index * 6 + 2] << 16) | (partial[index * 6 + 1] << 8) | partial[index * 6]

			value = twos_comp(value, 48)

			value = value * pow(10, -4)

			if index == 0:
				self.current_data["energyA_active_import"] = value
			elif index == 1:
				self.current_data["energyA_active_export"] = value
			elif index == 2:
				self.current_data["energyA_reactive_inductive"] = value
			elif index == 3:
				self.current_data["energyA_reactive_capacitive"] = value

			index += 1

		partial = partial[index * 6:]
		index = 0

		while index < 4:
			dt = partial[index * 16: index * 16 + 5]

			cumulative = (partial[index * 16 + 10] << 40) | (partial[index * 16 + 9] << 32) | \
						 (partial[index * 16 + 8] << 24) | (partial[index * 16 + 7] << 16) | \
						 (partial[index * 16 + 6] << 8) | partial[index * 16 + 5]

			max = (partial[index * 16 + 15] << 32) | (partial[index * 16 + 14] << 24) \
				  | (partial[index * 16 + 13] << 16) | (partial[index * 16 + 12] << 8) | partial[index * 16 + 11]

			# dt = twos_comp(dt, 40) * pow(10,-4)
			cumulative = twos_comp(cumulative, 48) * pow(10, -4)
			max = twos_comp(max, 40) * pow(10, -4)

			if index == 0:
				self.current_data["demandA_active_import_datetime"] = dt
				self.current_data["demandA_active_import_cumulative"] = cumulative
				self.current_data["demandA_active_import_max"] = max
			elif index == 1:
				self.current_data["demandA_active_export_datetime"] = dt
				self.current_data["demandA_active_export_cumulative"] = cumulative
				self.current_data["demandA_active_export_max"] = max
			elif index == 2:
				self.current_data["demandA_reactive_inductive_datetime"] = dt
				self.current_data["demandA_reactive_inductive_cumulative"] = cumulative
				self.current_data["demandA_reactive_inductive_max"] = max
			elif index == 3:
				self.current_data["demandA_reactive_capacitive_datetime"] = dt
				self.current_data["demandA_reactive_capacitive_cumulative"] = cumulative
				self.current_data["demandA_reactive_capacitive_max"] = max

			index += 1

		# print("partial: {}".format(partial))
		partial = partial[index * 16:]
		# print("new partial: {}".format(partial))

		index = 0
		while index < 4:

			# print("range for value: {}".format(partial[index * 6: index * 6 + 6]))

			value = (partial[index * 6 + 5] << 40) | (partial[index * 6 + 4] << 32) | (partial[index * 6 + 3] << 24) \
					| (partial[index * 6 + 2] << 16) | (partial[index * 6 + 1] << 8) | partial[index * 6]

			value = twos_comp(value, 48)

			value = value * pow(10, -4)

			if index == 0:
				self.current_data["energyB_active_import"] = value
			elif index == 1:
				self.current_data["energyB_active_export"] = value
			elif index == 2:
				self.current_data["energyB_reactive_inductive"] = value
			elif index == 3:
				self.current_data["energyB_reactive_capacitive"] = value

			index += 1

		partial = partial[index * 6:]

		index = 0

		while index < 4:
			dt = partial[index * 16: index * 16 + 5]

			cumulative = (partial[index * 16 + 10] << 40) | (partial[index * 16 + 9] << 32) | \
						 (partial[index * 16 + 8] << 24) | (partial[index * 16 + 7] << 16) | \
						 (partial[index * 16 + 6] << 8) | partial[index * 16 + 5]

			max = (partial[index * 16 + 15] << 32) | (partial[index * 16 + 14] << 24) \
				  | (partial[index * 16 + 13] << 16) | (partial[index * 16 + 12] << 8) | partial[index * 16 + 11]

			cumulative = twos_comp(cumulative, 48) * pow(10, -4)
			max = twos_comp(max, 40) * pow(10, -4)

			if index == 0:
				self.current_data["demandB_active_import_datetime"] = dt
				self.current_data["demandB_active_import_cumulative"] = cumulative
				self.current_data["demandB_active_import_max"] = max
			elif index == 1:
				self.current_data["demandB_active_export_datetime"] = dt
				self.current_data["demandB_active_export_cumulative"] = cumulative
				self.current_data["demandB_active_export_max"] = max
			elif index == 2:
				self.current_data["demandB_reactive_inductive_datetime"] = dt
				self.current_data["demandB_reactive_inductive_cumulative"] = cumulative
				self.current_data["demandB_reactive_inductive_max"] = max
			elif index == 3:
				self.current_data["demandB_reactive_capacitive_datetime"] = dt
				self.current_data["demandB_reactive_capacitive_cumulative"] = cumulative
				self.current_data["demandB_reactive_capacitive_max"] = max

			index += 1

	def generate_present_values(self):
		"""
		Generate the present values from the raw data and store them in the present_values dictionary
		:return: None
		"""
		keys = ["freq", "v1", "i1", "anglei1", "v3", "i3", "anglefp3", "anglev3", "v2", "i2", "anglefp2", "anglev2"]

		self.present_values['presDmd_record'] = {}
		self.present_values['present_values'] = {}
		payload = self.raw_present_values[3:]
		for index in range(4):
			current_demand = payload[8 * index: 8 * index + 8]
			key = "demand_" + str(index)
			self.present_values["presDmd_record"][key] = current_demand
		offset_payload = payload[32:]

		values = []

		for index in range(32):
			values.append(offset_payload[6 * index: 6 * index + 6])

		index = 0

		for value in values:
			if index < 12:
				twos_complement = convert_num_to_twos_comp(value)

				final_value = twos_complement * pow(10, -4)
				self.present_values["present_values"][keys[index]] = final_value

				index += 1
			else:
				break

		self.present_values["present_values"]["anglefp1"] = 0 + self.present_values["present_values"]["anglei1"]
		self.present_values["present_values"]["anglei2"] = self.present_values["present_values"]["anglefp2"] - \
														   self.present_values["present_values"]["anglev2"]

		self.present_values["present_values"]["anglei3"] = self.present_values["present_values"]["anglefp3"] - \
														   self.present_values["present_values"]["anglev3"]

		int_angle_i2 = int(self.present_values["present_values"]["anglei2"])
		fract_angle_i2 = self.present_values["present_values"]["anglei2"] - int_angle_i2

		int_angle_i3 = int(self.present_values["present_values"]["anglei3"])
		fract_angle_i3 = self.present_values["present_values"]["anglei3"] - int_angle_i3

		self.present_values["present_values"]["anglei2"] = int_angle_i3 + fract_angle_i2
		self.present_values["present_values"]["anglei3"] = int_angle_i2 + fract_angle_i3

		radi1 = (self.present_values["present_values"]["anglei1"] * math.pi) / 180.0
		radi2 = (self.present_values["present_values"]["anglei2"] * math.pi) / 180.0
		radi3 = (self.present_values["present_values"]["anglei3"] * math.pi) / 180.0

		radfp2 = (self.present_values["present_values"]["anglefp2"] * math.pi) / 180.0
		radfp3 = (self.present_values["present_values"]["anglefp3"] * math.pi) / 180.0

		self.present_values["present_values"]["s1"] = self.present_values["present_values"]["v1"] * \
													  self.present_values["present_values"]["i1"]
		self.present_values["present_values"]["s2"] = self.present_values["present_values"]["v2"] * \
													  self.present_values["present_values"]["i2"]
		self.present_values["present_values"]["s3"] = self.present_values["present_values"]["v3"] * \
													  self.present_values["present_values"]["i3"]

		self.present_values["present_values"]["p1"] = self.present_values["present_values"]["s1"] * math.cos(radi1)
		self.present_values["present_values"]["p2"] = self.present_values["present_values"]["s2"] * math.cos(radfp2)
		self.present_values["present_values"]["p3"] = self.present_values["present_values"]["s3"] * math.cos(radfp3)

		if math.sin(radi2) >= 0:
			sign2 = 1
		else:
			sign2 = -1

		if math.sin(radi3) >= 0:
			sign3 = 1
		else:
			sign3 = -1

		self.present_values["present_values"]["q1"] = self.present_values["present_values"]["s1"] * math.sin(radi1)
		self.present_values["present_values"]["q2"] = self.present_values["present_values"]["s2"] * \
													  math.sin(radfp2) * sign2
		self.present_values["present_values"]["q3"] = self.present_values["present_values"]["s3"] * \
													  math.sin(radfp3) * sign3

	def get_start_timestamp_in_block(self, interval_status_lsb: int, interval_status_msb: int,
									 block_end_timestamp: datetime) -> datetime:
		"""
		Get the start timestamp of the block
		:param interval_status_lsb: LSB of the interval status data
		:param interval_status_msb: MSB of the interval status data
		:param block_end_timestamp: end timestamp of the block
		:return: start timestamp of the block as a datetime object
		"""
		print("block_end_timestamp: ", block_end_timestamp)
		block_start_timestamp = block_end_timestamp
		_15_remainder = block_end_timestamp.minute % 15
		num_intervals = 0

		for idx in range(15, -1, -1):
			if idx >= 8:
				if interval_status_msb & (1 << (idx - 8)):
					num_intervals = idx
					break
			else:
				if interval_status_lsb & (1 << idx):
					num_intervals = idx
					break

		if _15_remainder > 0 and num_intervals > 0:
			block_start_timestamp = block_start_timestamp - datetime.timedelta(minutes=_15_remainder)
			num_intervals -= 1

		if num_intervals >= 0:
			block_start_timestamp = block_start_timestamp - datetime.timedelta(minutes=15 * num_intervals)

		return block_start_timestamp

	def table64_generate_payload(self, offset):
		payload = [0x3F, 0x00, 0x40, (offset & 0xFF0000) >> 16, (offset & 0x00FF00) >> 8, offset & 0x0000FF, 0x00, 0xB7]
		return payload

	def table2112_generate_payload(self, offset):
		payload = [0x3F, 0x08, 0x40, (offset & 0xFF0000) >> 16, (offset & 0x00FF00) >> 8, offset & 0x0000FF, 0x00, 0xB7]
		return payload

	def table2110_generate_payload(self):
		payload = [0x30, 0x08, 0x3E]
		return payload

	def table15_generate_payload(self):
		payload = [0x30, 0x00, 0x0F]
		return payload

	def append_interval_to_profile_data(
			self,
			table: list[int],
			interval_idx: int,
			interval_status: bool,
			interval_timestamp: datetime
	):
		"""
		append values of profile data to internal load_profile list.
		:param table: list of integers containing the data.
		:param interval_idx: index of the interval in the table.
		:param interval_status: status of the interval.
		:param interval_timestamp: datetime object for interval status
		:return: None
		"""
		new_datapoint = dict()

		if interval_status:
			# Para plantilla del equipo de Luz del Sur
			new_datapoint['kwh_del'] = table[interval_idx * 11 + 14] * 256 + table[interval_idx * 11 + 13]
			new_datapoint['kwh_rec'] = table[interval_idx * 11 + 16] * 256 + table[interval_idx * 11 + 15]
			new_datapoint['kvarh_del'] = table[interval_idx * 11 + 18] * 256 + table[interval_idx * 11 + 17]
			new_datapoint['kvarh_rec'] = table[interval_idx * 11 + 20] * 256 + table[interval_idx * 11 + 19]
			new_datapoint["timestamp"] = interval_timestamp.astimezone(utc_tz)
		else:
			new_datapoint['kwh_del'] = 0
			new_datapoint['kwh_rec'] = 0
			new_datapoint['kvarh_del'] = 0
			new_datapoint['kvarh_rec'] = 0
			new_datapoint["timestamp"] = interval_timestamp.astimezone(utc_tz)

		self.load_profile_data.append(new_datapoint)
		print("Timestamp leido in UTC:")
		print(new_datapoint["timestamp"])

	def append_interval_to_instrumentation_data(
			self,
			table: list[int],
			interval_idx: int,
			interval_status: bool,
			interval_timestamp: datetime
	):
		"""
		append values of instrumentation data to internal instrumentation list.
		:param table: list of integers containing the data.
		:param interval_idx: index of the interval in the table.
		:param interval_status: status of the interval.
		:param interval_timestamp: datetime object for interval status
		:return:
		"""
		new_datapoint = dict()

		if interval_status:
			# Para plantilla del equipo de Luz del Sur
			new_datapoint["voltage_a"] = (table[interval_idx * 11 + 14] * 256 + table[interval_idx * 11 + 13])
			new_datapoint["voltage_c"] = (table[interval_idx * 11 + 16] * 256 + table[interval_idx * 11 + 15])
			new_datapoint["current_a"] = (table[interval_idx * 11 + 18] * 256 + table[interval_idx * 11 + 17])
			new_datapoint["current_c"] = (table[interval_idx * 11 + 20] * 256 + table[interval_idx * 11 + 19])
			new_datapoint["timestamp"] = interval_timestamp.astimezone(utc_tz)
		else:
			new_datapoint["voltage_a"] = 0
			new_datapoint["voltage_c"] = 0
			new_datapoint["current_a"] = 0
			new_datapoint["current_c"] = 0
			new_datapoint["timestamp"] = interval_timestamp.astimezone(utc_tz)

		self.instrumentation_data.append(new_datapoint)
		print("Timestamp leido in UTC:")
		print(new_datapoint["timestamp"])

	def read_load_profile_intervals_from_block(
			self,
			table: list[int],
			block_end_timestamp: datetime,
			interval_status_lsb: int,
			interval_status_msb: int,
			first_block_flag: bool
	):
		"""
		Read the load profile intervals from a block of data
		:param table: list of integers containing the data.
		:param block_end_timestamp: end timestamp of the block.
		:param interval_status_lsb: Least Significant Byte of status interval
		:param interval_status_msb: Most Significant Byte of status interval
		:param first_block_flag: flag indicating if the block is the first one
		:return: None
		"""
		self.read_intervals_from_block(table, block_end_timestamp, interval_status_lsb, interval_status_msb,
									   first_block_flag, self.append_interval_to_profile_data)

	def read_instrumentation_intervals_from_block(
			self,
			table: list[int],
			block_end_timestamp: datetime,
			interval_status_lsb: int,
			interval_status_msb: int,
			first_block_flag: bool
	):
		"""
		Read the instrumentation profile intervals from a block of data
		:param table: list of integers containing the data.
		:param block_end_timestamp: end timestamp of the block.
		:param interval_status_lsb: Least Significant Byte of status interval
		:param interval_status_msb: Most Significant Byte of status interval
		:param first_block_flag: flag indicating if the block is the first one
		:return: None
		"""
		self.read_intervals_from_block(table, block_end_timestamp, interval_status_lsb, interval_status_msb,
									   first_block_flag, self.append_interval_to_instrumentation_data)

	def read_intervals_from_block(
			self,
			table: list[int],
			block_end_timestamp: datetime,
			interval_status_lsb: int,
			interval_status_msb: int,
			first_block_flag: bool,
			interval_parsing_function
	):
		current_interval_timestamp = block_end_timestamp
		_15_remainder = block_end_timestamp.minute % 15
		should_discard_first_interval = False
		first_valid_interval = -1

		if first_block_flag and (_15_remainder > 0):
			should_discard_first_interval = True

		for idx in range(15, -1, -1):
			if idx >= 8:
				if interval_status_msb & (1 << (idx - 8)):
					first_valid_interval = idx
					break
			else:
				if interval_status_lsb & (1 << idx):
					first_valid_interval = idx
					break

		for idx in range(first_valid_interval, -1, -1):
			if idx >= 8:
				if should_discard_first_interval:
					should_discard_first_interval = False
					current_interval_timestamp = block_end_timestamp - datetime.timedelta(minutes=_15_remainder)
					continue
				else:
					interval_status = interval_status_msb & (1 << (idx - 8))
					interval_parsing_function(table, idx, interval_status, current_interval_timestamp)
					current_interval_timestamp = current_interval_timestamp - datetime.timedelta(minutes=15)
			else:
				if should_discard_first_interval:
					should_discard_first_interval = False
					current_interval_timestamp = block_end_timestamp - datetime.timedelta(minutes=_15_remainder)
					continue
				else:
					interval_status = interval_status_lsb & (1 << idx)
					interval_parsing_function(table, idx, interval_status, current_interval_timestamp)
					current_interval_timestamp = current_interval_timestamp - datetime.timedelta(minutes=15)

	def read_load_profile_data_table(
			self,
			latest_timestamp_read: datetime.datetime
	) -> pd.DataFrame:
		"""
		Read the load profile data table
		:param latest_timestamp_read: latest timestamp read from the load profile data table
		:return: dataframe containing the load profile data
		"""
		continue_to_read_table64 = True
		first_block_flag = True
		offset = 0
		utc_target_timestamp = utc_tz.localize(latest_timestamp_read + datetime.timedelta(minutes=15))
		target_timestamp = utc_target_timestamp.astimezone(peru_tz)
		print(f"Intentando leer el timestamp desde las: {target_timestamp}")

		# Aquí empezaría el bucle si es que voy a leer varios mensajes a la vez
		while continue_to_read_table64:
			payload = self.table64_generate_payload(offset)
			print(f"Probado payload: {payload}")
			result = self.transport.send_ack()
			time.sleep(self.time_delay)
			if result:
				result = self.send_msg(payload)
				print(f"Resultado de leer TABLA 64:")
				print(result)
				if result["status"] == "failure":
					continue
				table = result['data']["block_0"] + result["data"]["block_1"]
				# save_data_to_excel(table)
				year = 2000 + int(table[3])
				month = table[4]
				day = table[5]
				hour = table[6]
				minute = int(table[7])
				interval_status_lsb = int(table[8])
				interval_status_msb = int(table[9])
				block_end_timestamp = peru_tz.localize(
					datetime.datetime.strptime(f"{year}-{month}-{day} {hour}:{minute}:00",
											   "%Y-%m-%d %H:%M:%S"))
				block_start_timestamp = self.get_start_timestamp_in_block(interval_status_lsb, interval_status_msb,
																		  block_end_timestamp)
				print("Block start timestamp:", block_start_timestamp)
				self.read_load_profile_intervals_from_block(table, block_end_timestamp, interval_status_lsb,
															interval_status_msb, first_block_flag)

				if target_timestamp < block_start_timestamp:
					offset += 0xB7
					first_block_flag = False
					print("TENEMOS que leer otro bloque...")
					time.sleep(4)
				else:
					print("FIN de lecturas de bloques...")
					continue_to_read_table64 = False

		df = pd.DataFrame(self.load_profile_data)

		df = df[df["timestamp"] >= target_timestamp.astimezone(utc_tz)]
		df["timestamp"] = df["timestamp"].dt.tz_localize(None)
		df.sort_values(by="timestamp", ascending=True, inplace=True)
		df.reset_index(drop=True, inplace=True)

		return df

	def read_instrumentation_data_table(
			self,
			latest_timestamp_read: datetime.datetime
	) -> pd.DataFrame:
		"""
		Read the instrumentation data table
		:param latest_timestamp_read: latest timestamp read from the instrumentation data table
		:return: dataframe containing the instrumentation data
		"""
		continue_to_read_table_2112 = True
		first_block_flag = True
		offset = 0
		utc_target_timestamp = utc_tz.localize(latest_timestamp_read + datetime.timedelta(minutes=15))
		target_timestamp = utc_target_timestamp.astimezone(peru_tz)
		print(f"Intentando leer el timestamp desde las: {target_timestamp}")

		# Aquí empezaría el bucle si es que voy a leer varios mensajes a la vez
		while continue_to_read_table_2112:
			payload = self.table2112_generate_payload(offset)
			result = self.transport.send_ack()
			time.sleep(self.time_delay)
			if result:
				result = self.send_msg(payload)
				print(f"Resultado de leer TABLA 2112 (0x840):")
				print(result)
				table = result['data']["block_0"] + result["data"]["block_1"]
				# save_data_to_excel(table)
				year = 2000 + int(table[3])
				month = table[4]
				day = table[5]
				hour = table[6]
				minute = int(table[7])
				interval_status_lsb = int(table[8])
				interval_status_msb = int(table[9])
				block_end_timestamp = peru_tz.localize(
					datetime.datetime.strptime(f"{year}-{month}-{day} {hour}:{minute}:00",
											   "%Y-%m-%d %H:%M:%S"))
				block_start_timestamp = self.get_start_timestamp_in_block(interval_status_lsb, interval_status_msb,
																		  block_end_timestamp)
				print("Block start timestamp:", block_start_timestamp)
				self.read_instrumentation_intervals_from_block(table, block_end_timestamp, interval_status_lsb,
															   interval_status_msb, first_block_flag)

				if target_timestamp < block_start_timestamp:
					offset += 0xB7
					first_block_flag = False
					print("TENEMOS que leer otro bloque...")
					time.sleep(1)
				else:
					print("FIN de lecturas de bloques...")
					continue_to_read_table_2112 = False

		df = pd.DataFrame(self.instrumentation_data)

		df = df[df["timestamp"] >= target_timestamp.astimezone(utc_tz)]
		df["timestamp"] = df["timestamp"].dt.tz_localize(None)
		df.sort_values(by="timestamp", ascending=True, inplace=True)
		df.reset_index(drop=True, inplace=True)

		return df

	def read_factors_table(self):
		"""
		Read the factors table
		:return: None
		"""
		payload = self.table2110_generate_payload()
		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			print(f"Resultado de leer TABLA 2110 (0x83E):")
			print(result)

	def read_constants_table(self):
		"""
		Read the constants table
		:return: None
		"""
		payload = self.table15_generate_payload()
		result = self.transport.send_ack()
		time.sleep(self.time_delay)
		if result:
			result = self.send_msg(payload)
			print(f"Resultado de leer TABLA 15 (0xF):")
			print(result)
