import time
from datetime import datetime

import pandas as pd

from app.a1800_reader.ansi_c_application_layer.ansi_application_layer import ANSIApplication


class A1800:
	def __init__(
			self,
			meter_address: int,
			meter_ip: str,
			meter_port: int,
			password: str,
			password_level: int,
			user: str,
			time_delay: float,
			logical_id: int
	):
		self.ansi_app = ANSIApplication(
			meter_address=meter_address,
			meter_ip=meter_ip,
			meter_port=meter_port,
			password=password,
			password_level=password_level,
			user=user,
			time_delay=time_delay,
			logical_id=logical_id
		)

	def open_and_auth(self) -> bool:
		"""
		Opens physical connection to meter, currently only a socket connection, then generate a logon and authentication
		to the meter.
		:return: True if connection is opened and authenticated successfully, False otherwise
		"""
		if not self.ansi_app.open():
			print("Error opening connection to meter")
			return False

		res = self.ansi_app.send_init()
		if res["status"] != "success":
			return False
		time.sleep(0.1)

		res = self.ansi_app.send_negotiate()
		if res["status"] != "success":
			return False
		time.sleep(0.1)

		res = self.ansi_app.send_logon()
		if res["status"] != "success":
			return False
		time.sleep(0.1)

		res = self.ansi_app.send_authenticate()
		if res["status"] != "success":
			return False
		time.sleep(0.1)

		return True

	def close(self):
		"""
		Closes physical connection to meter, currently only a socket connection
		:return: None
		"""
		self.ansi_app.close()

	def get_load_profile(self, start_timestamp: datetime) -> pd.DataFrame:
		"""
		Gets load profile data from meter
		:param start_timestamp: datetime object representing the start timestamp of the load profile data
		:return: pandas DataFrame with the load profile data
		"""
		return self.ansi_app.read_load_profile_data_table(start_timestamp)

	def get_instrumentation_profile(self, start_timestamp: datetime) -> (pd.DataFrame, pd.DataFrame):
		"""
		Gets instrumentation profile for the given start timestamp
		:param start_timestamp: datetime object representing the start timestamp of the interval data
		:return: pandas DataFrame with the instrumentation data
		"""
		return self.ansi_app.read_instrumentation_data_table(start_timestamp)
