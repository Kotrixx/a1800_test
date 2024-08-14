import socket
import threading
import binascii
import os
import datetime

# Configuración de los puertos y la dirección del medidor
LISTEN_PORT = 26000
METER_IP = '192.168.18.250'  # IP del medidor
METER_PORT = 20000

# Archivo donde se guardarán los logs
LOG_FILE = "packet_exchange.log"

# Crear el archivo de log si no existe
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        f.write("Intercambio de Paquetes:\n\n")


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

    return hex_string.upper()


def log_packet(direction, hex_data, special_message=None):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{direction} (Hex): {hex_data}\n")
        if special_message:
            f.write(f"** {special_message} **\n")
        f.write("-" * 50 + "\n")


def handle_client(client_socket):
    # Conectarse al medidor
    meter_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    meter_socket.connect((METER_IP, METER_PORT))

    # Generar la cadena hexadecimal para la fecha actual
    current_date = datetime.datetime.now()
    target_hex_string = date_to_hex_string(current_date)

    def forward(src, dst, direction):
        while True:
            data = src.recv(1024)
            if len(data) == 0:
                break
            hex_data = binascii.hexlify(data).decode('utf-8')

            # Verificar si el mensaje contiene la cadena hexadecimal
            if target_hex_string in hex_data:
                special_message = f"¡Cadena de fecha detectada en {direction}!"
                print(special_message)
                log_packet(direction, hex_data, special_message)
            else:
                log_packet(direction, hex_data)

            # Mostrar datos en hexadecimal en la consola
            print(f"{direction} (Hex): {hex_data}")
            dst.send(data)

    # Crear hilos para la transferencia bidireccional
    client_to_meter = threading.Thread(target=forward, args=(client_socket, meter_socket, "Cliente a Medidor"))
    meter_to_client = threading.Thread(target=forward, args=(meter_socket, client_socket, "Medidor a Cliente"))

    client_to_meter.start()
    meter_to_client.start()

    client_to_meter.join()
    meter_to_client.join()

    client_socket.close()
    meter_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(5)
    print(f"Escuchando en el puerto {LISTEN_PORT} y redirigiendo al {METER_IP}:{METER_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"Conexión aceptada de {addr}")
        handler = threading.Thread(target=handle_client, args=(client_socket,))
        handler.start()


if __name__ == "__main__":
    start_server()
