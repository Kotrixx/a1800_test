import sys

from crccheck.crc import CrcX25


def calc_crc(data: list[int]) -> list[int]:
	"""
	Calculate CRC for message to send
	:param data: list of integers of data to calculate CRC for
	:return: list containing a 16-bit CRC value
	"""
	crc_inst = CrcX25()
	crc_inst.process(data)
	crc_val = crc_inst.final()
	crc = [crc_val & 0xFF, ((crc_val >> 8) & 0xFF)]
	return crc


def conv_raw_to_list(raw_data: str) -> list[int]:
	"""
	Converts a string of raw data into a list of integers representing the ASCII values of the characters in the string.
	:param raw_data: string of raw data
	:return: list of integers representing the ASCII values of the characters in the string
	"""
	list_data = []
	for char in raw_data:
		if sys.version_info[0] < 3:
			list_data.append(ord(char))
		else:
			list_data.append(char)

	return list_data
