
from scapy.all import rdpcap, TCP, IP
from collections import Counter, defaultdict
from openpyxl import Workbook
import statistics
import os


def analizar_pcap(ruta_pcap):

    if not os.path.isfile(ruta_pcap):
        print(f" Archivo no encontrado: {ruta_pcap}")
        return

    print(f" Cargando archivo PCAP: {ruta_pcap}")

    paquetes = rdpcap(ruta_pcap)
    print(f"Total de paquetes cargados: {len(paquetes)}")

    # --- Contadores ---
    conteo_ips = Counter()
    conteo_puertos = Counter()
    tamanos_paquetes = []
    conteo_syn = Counter()
    conexiones_por_ip = defaultdict(set)

    # --- Procesamiento ---
    for pkt in paquetes:

        if IP in pkt:
            ip_origen = pkt[IP].src
            ip_destino = pkt[IP].dst
            conteo_ips[ip_origen] += 1
            tamanos_paquetes.append(len(pkt))

            # registrar conexiones
            conexiones_por_ip[ip_origen].add(ip_destino)

        # detectar puertos en TCP
        if TCP in pkt:
            puerto_destino = pkt[TCP].dport
            conteo_puertos[puerto_destino] += 1

            # detectar paquetes SYN sin ACK (posible escaneo)
            flags = pkt[TCP].flags
            if flags == "S":
                conteo_syn[ip_origen] += 1

    # --- Análisis heurístico ---
    anomalías = []

    # 1. IPs con tráfico elevado
    for ip, count in conteo_ips.items():
        if count > 500:  # umbral
            anomalías.append(f"IP {ip} envió un volumen inusualmente alto de paquetes: {count}")

    # 2. Muchos puertos diferentes → escaneo
    for ip, dests in conexiones_por_ip.items():
        if len(dests) > 50:
            anomalías.append(f"IP {ip} contactó más de 50 destinos diferentes (posible escaneo).")

    # 3. SYN flooding
    for ip, syn_count in conteo_syn.items():
        if syn_count > 100:
            anomalías.append(f"IP {ip} generó {syn_count} paquetes SYN → posible SYN flood o escaneo.")

    # 4. Paquetes muy grandes o pequeños
    if tamanos_paquetes:
        avg = statistics.mean(tamanos_paquetes)
        if avg < 60 or avg > 2000:
            anomalías.append(f"Tamaño promedio de paquetes inusual: {avg:.2f} bytes")

    # --- Clasificación de riesgo ---
    if len(anomalías) == 0:
        riesgo = "BAJO"
    elif len(anomalías) <= 2:
        riesgo = "MEDIO"
    else:
        riesgo = "ALTO"

    # --- Crear reporte Excel ---
    print("\n Generando reporte Excel...")

    wb = Workbook()
    ws = wb.active
    ws.title = "Reporte Analisis PCAP"

    ws.append(["Campo", "Valor"])
    ws.append(["Total de paquetes", len(paquetes)])
    ws.append(["Nivel de riesgo", riesgo])

    ws.append(["", ""])
    ws.append(["Anomalías detectadas", "Detalle"])

    if anomalías:
        for a in anomalías:
            ws.append(["Anomalía", a])
    else:
        ws.append(["Sin anomalías", "No se detectaron comportamientos sospechosos"])

    # Nombre dinámico
    nombre_reporte = "reporte_analisis_pcap.xlsx"
    wb.save(nombre_reporte)

    print(f" Reporte generado con éxito: {nombre_reporte}")

    return {
        "total_paquetes": len(paquetes),
        "anomalías": anomalías,
        "riesgo": riesgo,
        "reporte": nombre_reporte
    }


if __name__ == "__main__":
    analizar_pcap("test.pcap")
