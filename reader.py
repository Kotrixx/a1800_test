import re
from datetime import datetime


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


def extract_load_profile_values(hex_message):
    """
    Extrae los valores de carga de un mensaje hexadecimal de perfil de carga.
    Este es un ejemplo básico, debes ajustar las posiciones y tamaños según tu protocolo.
    """
    # Ajusta la posición de inicio basada en la estructura del mensaje
    start_pos = 120  # Este valor debe ajustarse según la estructura del mensaje real
    values = {}

    try:
        # Ajuste de tamaño de cada valor
        kWhDel_bytes = hex_message[start_pos:start_pos + 8]
        kVARhDel_bytes = hex_message[start_pos + 8:start_pos + 16]
        kWhRec_bytes = hex_message[start_pos + 16:start_pos + 24]
        kVARhRec_bytes = hex_message[start_pos + 24:start_pos + 32]

        # Verificar si es necesario ajustar el endianness (revertir bytes)
        # Prueba primero sin revertir y luego con revertir si no es correcto
        values['kWhDel'] = int(kWhDel_bytes, 16)
        values['kVARh-Del'] = int(kVARhDel_bytes, 16)
        values['kWh-Rec'] = int(kWhRec_bytes, 16)
        values['kVARh-Rec'] = int(kVARhRec_bytes, 16)

        # Si los valores no son correctos, prueba con:
        # values['kWhDel'] = int(kWhDel_bytes[::-1], 16)
        # values['kVARh-Del'] = int(kVARhDel_bytes[::-1], 16)
        # values['kWh-Rec'] = int(kWhRec_bytes[::-1], 16)
        # values['kVARh-Rec'] = int(kVARhRec_bytes[::-1], 16)

    except ValueError:
        print("Error al extraer valores de carga, revisa el formato del mensaje.")

    return values



def detect_last_load_profile(file_path):
    last_datetime = None
    last_load_message = None

    # Regex para detectar patrones AAMMDDHHmm en un string hexadecimal
    date_pattern = re.compile(r'([0-9a-fA-F]{10})')

    with open(file_path, 'r') as file:
        for line in file:
            # Filtrar para analizar solo los mensajes que podrían contener perfiles de carga
            if 'Medidor a Cliente (Hex):' in line:
                # Extraer la cadena hexadecimal del mensaje
                hex_message = line.split(': ')[1].strip()

                matches = date_pattern.findall(hex_message)

                for match in matches:
                    try:
                        timestamp = hex_to_datetime(match)

                        # Si la fecha/hora es válida y es la más reciente
                        if last_datetime is None or timestamp > last_datetime:
                            last_datetime = timestamp
                            last_load_message = hex_message
                    except ValueError:
                        # Ignorar patrones que no correspondan a fechas y horas válidas
                        continue

    if last_datetime:
        print(f"ultima carga medida en {last_datetime}:")
        print(f"mensaje hexadecimal: {last_load_message}")

        # Extraer y mostrar los valores de carga asociados
        load_profile_values = extract_load_profile_values(last_load_message)
        print(f"valores: {load_profile_values}")
    else:
        print("No se encontraron timestamps válidos en los mensajes.")


# Ruta al archivo de log (reemplazar con la ruta a tu archivo de log)
file_path = './packet_exchange.log'  # Actualiza esto con la ruta de tu archivo de log

# Detectar el último valor de carga medido
detect_last_load_profile(file_path)
