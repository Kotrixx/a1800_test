import datetime
import re


def detect_load_profile_messages(file_path):
    """
    Detecta mensajes relacionados con la lectura de la tabla 64 (perfil de carga) en un archivo de log.
    """
    first_block_flag = True

    request_pattern = re.compile(r'3f0040')  # Lectura de la tabla 64
    response_pattern = re.compile(r'ee01c0[0-9a-fA-F]{4}f8')  # Parte de la respuesta del medidor

    last_request = None
    last_response = None
    process_next = False

    with open(file_path, 'r') as file:
        for line in file:
            if 'Cliente a Medidor (Hex):' in line:
                hex_message = line.split(': ')[1].strip()

                if request_pattern.search(hex_message):
                    last_request = hex_message
                    print(f"Solicitud identificada: {hex_message}")
                    process_next = True

            elif 'Medidor a Cliente (Hex):' in line and process_next:
                hex_message = line.split(': ')[1].strip()

                if response_pattern.search(hex_message):
                    last_response = hex_message
                    pure_message = hex_message[12:]
                    table = [int(pure_message[i:i + 2], 16) for i in range(0, len(pure_message), 2)]
                    hex_message2 = [(last_response[i:i + 2], 16) for i in range(0, len(last_response), 2)]

                    print(f"Tabla pura: {table}")
                    print(f"tamaño: {len(table)}")
                    print(f"\nOK: {table[0]}, Data: {table[1]}, {table[2]}")
                    # PURAMENTE FECHA Y DATOS
                    table = table[3::]
                    print(table)
                    print(f"First Date: {table[0]}-{table[1]}-{table[2]} {table[3]}:{table[4]}")
                    print(len(table))
                    # table 5 - 6 son los bits
                    block_data = 7 + 11 * 16
                    block_data_cp = block_data
                    i = 1
                    while len(table) > block_data_cp:
                        sub_table = table[block_data * i:block_data * (i + 1)]
                        print(f"\nElements {i}: {sub_table}\n")

                        process_block(sub_table, first_block_flag)
                        i = i + 1
                        block_data_cp = block_data + block_data_cp
                    process_next = False


def process_block(table, first_block_flag):
    """
    Procesa un bloque de datos para extraer la fecha y los intervalos.
    """
    block_end_timestamp = datetime.datetime(2000 + table[0], table[1], table[2], table[3], table[4])
    interval_status_lsb = table[5]
    interval_status_msb = table[6]

    print(f"Procesando bloque con fecha de fin: {block_end_timestamp}")

    read_intervals_from_block(
        table,
        block_end_timestamp,
        interval_status_lsb,
        interval_status_msb,
        first_block_flag,
        example_parsing_function
    )


def read_intervals_from_block(
        table: list[int],
        block_end_timestamp: datetime.datetime,
        interval_status_lsb: int,
        interval_status_msb: int,
        first_block_flag: bool,
        interval_parsing_function
):
    current_interval_timestamp = block_end_timestamp
    _15_remainder = block_end_timestamp.minute % 15
    should_discard_first_interval = False
    first_valid_interval = -1

    # Verificar si se debe descartar el primer intervalo
    if first_block_flag and (_15_remainder > 0):
        should_discard_first_interval = True

    # Determinar el primer intervalo válido
    for idx in range(15, -1, -1):
        if idx >= 8:
            if interval_status_msb & (1 << (idx - 8)):
                first_valid_interval = idx
                break
        else:
            if interval_status_lsb & (1 << idx):
                first_valid_interval = idx
                break

    # Procesar los intervalos desde el primer válido hacia atrás
    for idx in range(first_valid_interval, -1, -1):
        if idx >= 8:
            if should_discard_first_interval:
                should_discard_first_interval = False
                current_interval_timestamp = block_end_timestamp - datetime.timedelta(minutes=_15_remainder)
                continue
            else:
                interval_status = interval_status_msb & (1 << (idx - 8))
                interval_parsing_function(table, idx, interval_status, current_interval_timestamp)
                current_interval_timestamp -= datetime.timedelta(minutes=15)
        else:
            if should_discard_first_interval:
                should_discard_first_interval = False
                current_interval_timestamp = block_end_timestamp - datetime.timedelta(minutes=_15_remainder)
                continue
            else:
                interval_status = interval_status_lsb & (1 << idx)
                interval_parsing_function(table, idx, interval_status, current_interval_timestamp)
                current_interval_timestamp -= datetime.timedelta(minutes=15)


def example_parsing_function(table, idx, interval_status, current_interval_timestamp):
    # Función de ejemplo que imprime la información del intervalo procesado
    if interval_status:
        print(f"Interval {idx} at {current_interval_timestamp} is active.")
    else:
        print(f"Interval {idx} at {current_interval_timestamp} is inactive.")


# Uso de ejemplo:
file_path = './packet_exchange.log'
detect_load_profile_messages(file_path)
