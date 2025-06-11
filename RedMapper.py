import argparse
import socket
from scapy.all import ARP, Ether, srp, sniff, conf
import nmap
import matplotlib.pyplot as plt
import networkx as nx

verbose = False

def vprint(msg):
    if verbose:
        print(msg)

DEVICE_TYPES = {
    'windows': 'Windows',
    'linux': 'Linux',
    'printer': 'Impresora',
    'iot': 'IoT',
    'router': 'Router',
    'firewall': 'Firewall',
    'unknown': 'Desconocido'
}

def mostrar_banner():
    rojo = "\033[91m"
    reset = "\033[0m"
    banner = (f"""{rojo}
 ██▀███  ▓█████ ▓█████▄  ███▄ ▄███▓ ▄▄▄       ██▓███   ██▓███  ▓█████  ██▀███  
▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒
▓██ ░▄█ ▒▒███   ░██   █▌▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒▓██░ ██▓▒▒███   ▓██ ░▄█ ▒
▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄  
░██▓ ▒██▒░▒████▒░▒████▓ ▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░▒██▒ ░  ░░▒████▒░██▓ ▒██▒
░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒ ░  ░      ░  ▒   ▒▒ ░░▒ ░     ░▒ ░      ░ ░  ░  ░▒ ░ ▒░
  ░░   ░    ░    ░ ░  ░ ░      ░     ░   ▒   ░░       ░░          ░     ░░   ░ 
   ░        ░  ░   ░           ░         ░  ░                     ░  ░   ░     
                 ░                                                             
                                            Author: @4NTR4xX 
{reset}""")
    print(banner)

def identificar_dispositivo(hostname, so):
    hn = hostname.lower()
    so_lower = so.lower()
    if 'printer' in hn or 'printer' in so_lower:
        return DEVICE_TYPES['printer']
    elif 'router' in hn or 'gateway' in hn or 'router' in so_lower:
        return DEVICE_TYPES['router']
    elif 'cam' in hn or 'iot' in hn or 'iot' in so_lower:
        return DEVICE_TYPES['iot']
    elif 'win' in hn or 'windows' in so_lower:
        return DEVICE_TYPES['windows']
    elif 'linux' in hn or 'linux' in so_lower:
        return DEVICE_TYPES['linux']
    elif 'firewall' in hn or 'firewall' in so_lower:
        return DEVICE_TYPES['firewall']
    else:
        return DEVICE_TYPES['unknown']

def escaneo_pasivo(duracion):
    print(f"[+] Escuchando tráfico de red por {duracion} segundos para detectar dispositivos...")
    dispositivos = set()
    def capturar(pkt):
        if pkt.haslayer(ARP):
            dispositivos.add(pkt.psrc)
    sniff(prn=capturar, timeout=duracion, store=False)
    return list(dispositivos)

def escaneo_red(interface):
    print(f"[+] Escaneando red en la interfaz {interface}...")
    conf.verb = 0
    ip = conf.route.route("0.0.0.0")[1]
    target = f"{ip}/24"
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp
    result = srp(pkt, timeout=3, iface=interface, inter=0.1)[0]
    return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for snd, rcv in result]

def escaneo_puertos(ip):
    scanner = nmap.PortScanner()
    puertos = []
    try:
        scanner.scan(ip, arguments="-sS -sV -n -T4 -f")
        for port in scanner[ip].get('tcp', {}):
            estado = scanner[ip]['tcp'][port]['state']
            servicio = scanner[ip]['tcp'][port]['name']
            version = scanner[ip]['tcp'][port].get('version', '')
            puertos.append(f"{port} - {servicio.upper()} {version} - {estado}")
    except:
        pass
    return puertos

def detectar_so(ip):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, arguments='-O -Pn')
        if 'osmatch' in scanner[ip] and scanner[ip]['osmatch']:
            return scanner[ip]['osmatch'][0]['name']
    except:
        pass
    return "SO desconocido"

def generar_html(nombre_empresa, dispositivos, salida):
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe de Red - {nombre_empresa}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; }}
        h1 {{ text-align: center; color: #333; }}
        .dispositivo {{ background: #fff; padding: 15px; margin-bottom: 10px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.1); }}
        .puerto {{ margin-left: 20px; color: #555; }}
    </style>
</head>
<body>
    <h1>Informe de Red - {nombre_empresa}</h1>
"""

    for d in dispositivos:
        html += f"""<div class="dispositivo">
<h2>{d['tipo']} - {d['ip']} - {d['so']}</h2>"""
        if d['puertos']:
            html += "<ul>"
            for p in d['puertos']:
                html += f"<li class='puerto'>{p}</li>"
            html += "</ul>"
        html += "</div>\n"

    html += "</body>\n</html>"

    with open(salida.replace(".pdf", ".html"), "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Reporte HTML generado en: {salida.replace('.pdf', '.html')}")
def graficar_topologia(dispositivos, salida_img):
    G = nx.Graph()
    ip_local = conf.route.route("0.0.0.0")[1]
    nodo_central = f"Tú ({ip_local})"
    G.add_node(nodo_central)

    for d in dispositivos:
        nombre = f"{d['ip']}\n{d['so']}"
        G.add_node(nombre)
        G.add_edge(nodo_central, nombre)

    pos = nx.spring_layout(G)
    plt.figure(figsize=(12, 7))
    nx.draw(G, pos, with_labels=True, node_color='lightgreen', edge_color='gray',
            node_size=2500, font_size=9, font_weight='bold')
    plt.title("Topología de Red", fontsize=14)
    plt.savefig(salida_img)
    plt.close()
    print(f"[+] Topología de red guardada en {salida_img}")

def main():
    global verbose
    mostrar_banner()
    parser = argparse.ArgumentParser(description="RedMapper - Mapeador de red y reporte")
    parser.add_argument("-I", "--interfaces", nargs='+', required=True, help="Interfaces de red a escanear")
    parser.add_argument("-o", "--output", required=True, help="Nombre del HTML de salida")
    parser.add_argument("--case", required=True, help="Nombre de la empresa o caso")
    parser.add_argument("--sniff", type=int, default=30, help="Duración del escaneo pasivo (segundos)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar salida detallada del proceso")
    args = parser.parse_args()
    
    verbose = args.verbose

    vprint("[*] Iniciando escaneo pasivo...")
    dispositivos_pasivos = escaneo_pasivo(args.sniff)

    for interfaz in args.interfaces:
        vprint(f"[*] Escaneando interfaz {interfaz}...")
        activos = escaneo_red(interfaz)
        for disp in activos:
            if disp['ip'] not in dispositivos_pasivos:
                dispositivos_pasivos.append(disp['ip'])

    dispositivos_finales = []
    for ip in dispositivos_pasivos:
        try:
            vprint(f"[+] Analizando dispositivo {ip}...")
            hostname = socket.getfqdn(ip)
            so = detectar_so(ip)
            tipo = identificar_dispositivo(hostname, so)
            puertos = escaneo_puertos(ip)
            dispositivos_finales.append({
                "ip": ip,
                "tipo": tipo,
                "puertos": puertos,
                "so": so
            })
        except Exception as e:
            print(f"[-] Error al analizar {ip}: {e}")
            continue

    graficar_topologia(dispositivos_finales, "topologia.png")
    generar_html(args.case, dispositivos_finales, args.output)

if __name__ == "__main__":
    main()
