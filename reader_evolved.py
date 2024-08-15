import re
from datetime import datetime, timedelta


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


def hex_to_datetime_from_message(hex_string):
    """Convierte una subcadena de un mensaje hexadecimal en un objeto datetime."""
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


def extract_load_profile_values(hex_message):
    """
    Extrae los valores de carga de un mensaje hexadecimal de perfil de carga.
    Este es un ejemplo básico, debes ajustar las posiciones y tamaños según tu protocolo.
    """
    start_pos = 22  # Ajustar según la estructura del mensaje real
    values = {}

    try:
        kWhDel_bytes = hex_message[start_pos:start_pos + 8]
        kVARhDel_bytes = hex_message[start_pos + 8:start_pos + 16]
        kWhRec_bytes = hex_message[start_pos + 16:start_pos + 24]
        kVARhRec_bytes = hex_message[start_pos + 24:start_pos + 32]

        values['kWhDel'] = int(kWhDel_bytes, 16)
        values['kVARh-Del'] = int(kVARhDel_bytes, 16)
        values['kWh-Rec'] = int(kWhRec_bytes, 16)
        values['kVARh-Rec'] = int(kVARhRec_bytes, 16)

    except ValueError:
        print("Error al extraer valores de carga, revisa el formato del mensaje.")

    return values


def extract_datetime_from_pure_message(pure_message):
    """
    Extrae la fecha y hora del mensaje puro formateado.
    """
    pure_message_hex = pure_message.replace("0x", "").replace(" ", "")
    date_time_hex = pure_message_hex[6:16]  # Extraemos los 5 bytes relevantes (10 caracteres hexadecimales)

    date_time = hex_to_datetime_from_message(date_time_hex)
    return date_time


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

    # Fecha y hora
    fecha_hex = [x.replace('0x', '') for x in pure_message_list[3:8]]
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
    parsed_message['Cantidad de Intervalos'] = int(pure_message_list[8].replace('0x', ''), 16)

    # Valores iniciales (valor1, valor2, valor3)
    parsed_message['Valor 1'] = pure_message_list[9]
    parsed_message['Valor 2'] = pure_message_list[10]
    parsed_message['Valor 3'] = pure_message_list[11]

    # Información de los intervalos
    intervalos = []
    intervalo_base_idx = 12
    for i in range(parsed_message['Cantidad de Intervalos']):
        # Verificar que hay suficientes elementos para este intervalo
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
                        date_time = extract_datetime_from_pure_message(pure_message_formatted)
                        print(f"Fecha y hora extraídas: {date_time}")
                    except ValueError as e:
                        print(f"Advertencia: {e}")

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