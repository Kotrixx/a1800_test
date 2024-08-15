import datetime

from a1800_reader.ansi_c_application_layer.ansi_application_layer import utc_tz

load_profile_data = []


def get_start_timestamp_in_block(interval_status_lsb: int, interval_status_msb: int,
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


def read_load_profile_intervals_from_block(
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
    read_intervals_from_block(table, block_end_timestamp, interval_status_lsb, interval_status_msb,
                              first_block_flag, append_interval_to_profile_data)


def read_intervals_from_block(
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


def append_interval_to_profile_data(
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

    load_profile_data.append(new_datapoint)
    print("Timestamp leido in UTC:")
    print(new_datapoint["timestamp"])
