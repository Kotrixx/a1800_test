def convert_num_to_twos_comp(value: list[int]) -> int:
	"""
	Converts a list of 6 bytes to a 48-bit two's complement number
	:param value: list of 6 bytes
	:return: 48-bit two's complement number
	"""
	number = (value[5] << 40) | (value[4] << 32) | (value[3] << 24) | (value[2] << 16) | \
			 (value[1] << 8) | value[0]

	twos_complement = twos_comp(number, 6 * 8)

	return twos_complement


def twos_comp(val: int, bits: int) -> int:
	"""
	Calculate the twos complement of a number with a given number of bits
	:param val: number to calculate twos complement of
	:param bits: number of bits to use
	:return: twos complement of val
	"""
	if (val & (1 << (bits-1))) != 0:
		val = val - (1 << bits)
	return val
