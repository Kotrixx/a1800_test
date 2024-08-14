import serial
import time


def send_at_command(port, commands, timeout=1):
    responses = []
    try:
        with serial.Serial(port, 115200, timeout=timeout) as ser:
            for command in commands:
                ser.write((command + '\r\n').encode())

                time.sleep(0.5)

                response = ser.readlines()
                response = [line.decode('utf-8').strip() for line in response]
                responses.append((command, response))
    except serial.SerialException as e:
        return f"Error de conexión: {e}"

    return responses


def interpret_csq(csq_value):
    if 2 <= csq_value <= 9:
        return -109 + (csq_value - 2) * 2, "Marginal"
    elif 10 <= csq_value <= 14:
        return -93 + (csq_value - 10) * 2, "OK"
    elif 15 <= csq_value <= 19:
        return -83 + (csq_value - 15) * 2, "Good"
    elif 20 <= csq_value <= 30:
        return -73 + (csq_value - 20) * 2, "Excellent"
    elif csq_value == 31:
        return -51, "Excellent"
    elif csq_value == 99:
        return "Indefinido", "Unknown"
    else:
        return "Unknown", "Unknown"


def process_cgdcont(response):
    for line in response:
        if "+CGDCONT" in line:
            parts = line.split(",")
            cid = parts[0].split(":")[1].strip()
            pdp_type = parts[1].strip('"')
            apn = parts[2].strip('"')
            pdp_addr = parts[3].strip('"')
            return f"Context ID: {cid}, PDP Type: {pdp_type}, APN: {apn}, PDP Address: {pdp_addr}"
    return "Unknown CGDCONT response"


if __name__ == "__main__":
    port = "/dev/ttyUSB2"  # Device por defecto de los modems Trolink
    commands = [
        "AT",
        "AT+CSQ",
        "AT+GMM",
        "AT+CGDCONT?"
    ]

    responses = send_at_command(port, commands)

    for command, response in responses:
        print(f"Comando: {command}")
        if command == "AT+CSQ":
            for line in response:
                if "+CSQ" in line and ":" in line:
                    parts = line.split(":")[1].split(",")
                    rssi = int(parts[0].strip())
                    if rssi == 99:
                        print("Señal RSSI: Indefinido")
                    else:
                        rssi_dbm, condition = interpret_csq(rssi)
                        print(f"Señal RSSI: {rssi} ({rssi_dbm} dBm) - Condición: {condition}")
        elif command == "AT+CGDCONT?":
            print("Respuesta: " + process_cgdcont(response))
        else:
            print("Respuesta: " + ", ".join(response)+"\n")
