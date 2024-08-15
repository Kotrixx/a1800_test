import re
from datetime import datetime, timedelta
import pytz

from reader_evolved import hex_to_datetime_from_message

peru_tz = pytz.timezone('America/Lima')  # Ejemplo de zona horaria para Perú
utc_tz = pytz.utc

class LoadProfileInterpreter:

    def __init__(self, transport=None, time_delay=1.0):
        self.transport = transport
        self.time_delay = time_delay

    def get_start_timestamp_in_block(self, interval_status_lsb: int, interval_status_msb: int,
                                     block_end_timestamp: datetime) -> datetime:
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
            block_start_timestamp = block_start_timestamp - timedelta(minutes=_15_remainder)
            num_intervals -= 1

        if num_intervals >= 0:
            block_start_timestamp = block_start_timestamp - timedelta(minutes=15 * num_intervals)

        return block_start_timestamp

    def append_interval_to_profile_data(self, table, idx, interval_status, timestamp):
        # Aquí procesas cada intervalo
        print(f"Procesando intervalo {idx} con timestamp {timestamp} y status {interval_status}")

def hex_to_datetime(hex_string):
    """Convierte una cadena hexadecimal en un objeto datetime."""
    try:
        year = int(hex_string[0:2], 16) + 2000
        month = int(hex_string[2:4], 16)
        day = int(hex_string[4:6], 16)
        hour = int(hex_string[6:8], 16)
        minute = int(hex_string[8:10], 16)

        # Verificar que los valores sean válidos y plausibles
        if not (2020 <= year <= 2025 and 1 <= month <= 12 and 1 <= day <= 31 and 0 <= hour < 24 and 0 <= minute < 60):
            raise ValueError("Fecha y hora fuera de rango o inválidas.")

        return datetime(year, month, day, hour, minute)
    except (ValueError, IndexError):
        raise ValueError("Formato de fecha y hora inválido.")

def parse_hex_message(pure_message):
    """
    Parsea un mensaje hexadecimal siguiendo la estructura dada:
    - Los primeros 3 hexadecimales: OK y cantidad de datos.
    - Los siguientes 5 hexadecimales: fecha y hora.
    - 2 hexadecimales: cantidad de intervalos.
    - 3 hexadecimales: valor1, valor2, valor3.
    - 2 hexadecimales para cada uno: kWh-del, kVarh-del, kWh-rec, kVarh-rec por cada intervalo.
    """

    pure_message_list = pure_message.split(" ")

    if len(pure_message_list) < 14:
        print("El mensaje es demasiado corto para contener todos los campos necesarios.")
        return None

    parsed_message = {}

    # OK
    parsed_message['OK'] = pure_message_list[0]

    # Cantidad de datos
    parsed_message['Cantidad de Datos'] = int(pure_message_list[1].replace('0x', '') + pure_message_list[2].replace('0x', ''), 16)

    intervalos = []
    idx = 3
    while idx < len(pure_message_list):
        # Fecha y hora
        fecha_hex = [pure_message_list[idx + i].replace('0x', '') for i in range(5)]
        try:
            fecha_hora = hex_to_datetime_from_message("".join(fecha_hex))
            # Redondear al intervalo anterior de 15 minutos
            fecha_hora = fecha_hora - timedelta(minutes=fecha_hora.minute % 15,
                                                seconds=fecha_hora.second,
                                                microseconds=fecha_hora.microsecond)
            parsed_message['Fecha y Hora'] = fecha_hora
        except ValueError as e:
            print(f"Advertencia: {e}. Se omitirá este mensaje.")
            return None

        # Cantidad de intervalos
        cantidad_intervalos = int(pure_message_list[idx + 5].replace('0x', ''), 16)

        # Valores iniciales (valor1, valor2, valor3)
        parsed_message['Valor 1'] = pure_message_list[idx + 6]
        parsed_message['Valor 2'] = pure_message_list[idx + 7]
        parsed_message['Valor 3'] = pure_message_list[idx + 8]

        # Procesar los intervalos
        intervalo_base_idx = idx + 9
        for i in range(cantidad_intervalos):
            if intervalo_base_idx + 3 < len(pure_message_list):
                # Convertir los valores a decimales y calcular timestamp
                timestamp = fecha_hora - timedelta(minutes=15 * i)
                kwh_del = int(pure_message_list[intervalo_base_idx].replace('0x', ''), 16) / 100.0
                kvarh_del = int(pure_message_list[intervalo_base_idx + 1].replace('0x', ''), 16) / 100.0
                kwh_rec = int(pure_message_list[intervalo_base_idx + 2].replace('0x', ''), 16) / 100.0
                kvarh_rec = int(pure_message_list[intervalo_base_idx + 3].replace('0x', ''), 16) / 100.0

                intervalo = {
                    'Timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'kWh-del': f"{kwh_del:.2f}",
                    'kVarh-del': f"{kvarh_del:.2f}",
                    'kWh-rec': f"{kwh_rec:.2f}",
                    'kVarh-rec': f"{kvarh_rec:.2f}",
                }
                intervalos.append(intervalo)
                intervalo_base_idx += 4  # Cada intervalo consta de 4 bytes
            else:
                print(f"Advertencia: No hay suficientes datos para el intervalo {i + 1}.")
                break

        # Avanzar al siguiente bloque de datos
        idx = intervalo_base_idx

    parsed_message['Intervalos'] = intervalos

    return parsed_message

def detect_load_profile_messages(file_path):
    """
    Detecta mensajes relacionados con la lectura de la tabla 64 (perfil de carga) en un archivo de log.
    """
    request_pattern = re.compile(r'3f0040')
    response_pattern = re.compile(r'ee01c0[0-9a-fA-F]{4}f8')

    last_request = None
    last_response = None

    with open(file_path, 'r') as file:
        for line in file:
            if 'Cliente a Medidor (Hex):' in line:
                hex_message = line.split(': ')[1].strip()

                if request_pattern.search(hex_message):
                    last_request = hex_message
                    print(f"Solicitud identificada: {hex_message}")

            elif 'Medidor a Cliente (Hex):' in line:
                hex_message = line.split(': ')[1].strip()

                if response_pattern.search(hex_message):
                    last_response = hex_message
                    print(f"Respuesta identificada: {hex_message}")

                    pure_message = hex_message[12:]
                    pure_message_formatted = " ".join([f"0x{pure_message[i:i + 2]}" for i in range(0, len(pure_message), 2)])
                    print(f"Mensaje puro formateado: {pure_message_formatted}")

                    try:
                        parsed_message = parse_hex_message(pure_message_formatted)
                        if parsed_message:
                            print(f"Mensaje parseado:\n")
                            for key, value in parsed_message.items():
                                if key == 'Intervalos':
                                    for intervalo in value:
                                        print(f"{intervalo['Timestamp']} - kWh-del: {intervalo['kWh-del']}, "
                                              f"kVarh-del: {intervalo['kVarh-del']}, kWh-rec: {intervalo['kWh-rec']}, "
                                              f"kVarh-rec: {intervalo['kVarh-rec']}\n")
                                else:
                                    print(f"{key}: {value}")
                    except ValueError as e:
                        print(f"Error al parsear el mensaje: {e}")

    if last_request and last_response:
        print("\nÚltima solicitud y respuesta de perfil de carga detectadas:")
        print(f"Solicitud: {last_request}")
        print(f"Respuesta: {last_response}")
    else:
        print("No se encontraron solicitudes o respuestas completas de perfil de carga.")

# Ruta al archivo de log (reemplazar con la ruta a tu archivo de log)
file_path = './packet_exchange.log'

# Detectar los mensajes de perfil de carga
detect_load_profile_messages(file_path)
