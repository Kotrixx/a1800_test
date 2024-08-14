import datetime


def date_to_hex_string(date):
    # Año - 2000
    year = date.year - 2000
    year_hex = f"{year:02x}"

    # Mes
    month = date.month
    month_hex = f"{month:02x}"

    # Día
    day = date.day
    day_hex = f"{day:02x}"

    # Hora
    hour = date.hour
    hour_hex = f"{hour:02x}"

    # Minuto
    minute = date.minute
    minute_hex = f"{minute:02x}"

    # Concatenar todos los valores en una sola cadena
    hex_string = year_hex + month_hex + day_hex + hour_hex + minute_hex

    # Mostrar resultados
    print(f"Fecha: {date.strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"Cadena en hexadecimal: {hex_string.upper()}")

    return hex_string.upper()


# Fecha actual
current_date = datetime.datetime.now()

# Convertir la fecha actual a una cadena en hexadecimal
date_to_hex_string(current_date)

# Ejemplo con una fecha específica
specific_date = datetime.datetime(2024, 8, 12, 12, 45, 0)
date_to_hex_string(specific_date)
