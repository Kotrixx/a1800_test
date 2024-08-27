import datetime
import json
import re
import pandas as pd

last_block = []
report = {}
report2 = []


def detect_load_profile_messages(file_path):
    """
    Detecta mensajes relacionados con la lectura de la tabla 64 (perfil de carga) en un archivo de log.
    """
    first_block_flag = True
    first_packet_flag = True
    request_pattern = re.compile(r'3f0040')
    response_pattern = re.compile(r'ee')

    table_64_flag = False
    process_next = True
    with open(file_path, 'r') as file:
        global last_block

        for line in file:
            if 'Cliente a Medidor (Hex):' in line:
                hex_message = line.split(': ')[1].strip()

                if request_pattern.search(hex_message):
                    print(f"Solicitud de tabla 64 identificada: {hex_message}")
                    table_64_flag = True
            elif 'Medidor a Cliente (Hex):' in line and process_next and table_64_flag:
                hex_message = line.split(': ')[1].strip()  # Datos de capa 2 y de capa 7
                if response_pattern.search(hex_message) and len(hex_message) > 18:
                    hex_message_bytes = [hex_message[i:i + 2] for i in range(0, len(hex_message), 2)]
                    link_layer = hex_message_bytes[:6]
                    control_byte = link_layer[2]
                    seq_byte = link_layer[3]
                    packet_number = int(seq_byte, 16)

                    if packet_number == 0:
                        process_next = False
                    packet_length = link_layer[4] + link_layer[5]
                    packet_length = int(packet_length, 16)
                    print("packet_length", packet_length)
                    multiple_data_packets = bool(int(control_byte, 16) & (1 << 7))
                    first_data_packet = bool(int(control_byte, 16) & (1 << 6))
                    print(multiple_data_packets)

                    pure_message = hex_message[12:]
                    pure_message = pure_message[:-2]  # Removiendo bytes de CRC
                    table = [int(pure_message[i:i + 2], 16) for i in range(0, len(pure_message), 2)]

                    print(f"Tabla pura: {table}")
                    print(f"Tamaño: {len(table)}")
                    print(f"\nOK: {table[0]}, Data: {table[1]}, {table[2]}")

                    if first_packet_flag:
                        table = table[3:]
                    else:
                        table = table[1:]
                    print(f"First Date: {table[0]}-{table[1]}-{table[2]} {table[3]}:{table[4]}")
                    print(len(table))

                    block_data = 7 + 11 * 16
                    block_data_cp = block_data
                    i = 1

                    while len(table) > block_data_cp:
                        last_block_size = len(last_block)

                        if last_block_size != 0:
                            index = 183 - last_block_size
                            sub_block = last_block + table[:index]
                            process_block(sub_block, first_block_flag)
                            last_block = []
                            table = table[index:]
                            print("actualizando valores: ", table)
                        else:
                            sub_table = table[block_data_cp:block_data_cp + 183]
                            print(f"\nElements {i}: {sub_table}\n")
                            print(f"Size: {len(sub_table)}")

                            if len(sub_table) == 183:
                                process_block(sub_table, first_block_flag)
                            else:
                                print(f"Último bloque detectado con {len(sub_table)} elementos.")
                                last_block = sub_table
                                first_packet_flag = False
                                break

                        i += 1
                        block_data_cp += 183

                    first_block_flag = True


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
    global report
    date_str = current_interval_timestamp.strftime('%Y-%m-%d')
    time_str = current_interval_timestamp.strftime('%H:%M')

    if date_str not in report:
        report[date_str] = []

    interval_data = {
        "interval": idx,
        "status": "active" if interval_status else "inactive",
        "time": time_str
    }

    report[date_str].append(interval_data)
    report2.append(interval_data)

    if interval_status:
        print(f"Interval {idx} at {current_interval_timestamp} is active.")
    else:
        print(f"Interval {idx} at {current_interval_timestamp} is inactive.")


# Uso de ejemplo:
file_path = './packet_exchange.log'
detect_load_profile_messages(file_path)
data = report

rows = []

for date, intervals in data.items():
    for interval in intervals:
        rows.append({
            "Date": date,
            "Interval": interval["interval"],
            "Status": interval["status"],
            "Time": interval["time"]
        })

# Crear un DataFrame con los datos tabulares
df = pd.DataFrame(rows)

# Escribir el DataFrame a un archivo Excel
df.to_excel('report_from_json.xlsx', index=False)

print("Reporte generado en 'report_from_json.xlsx'")

with open('report.json', 'w') as json_file:
    json.dump(report, json_file, indent=4)