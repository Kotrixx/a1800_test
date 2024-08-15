import datetime


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
                                   first_block_flag, self.append_interval_to_profile_data)

