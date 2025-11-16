
import requests
import pandas as pd
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import os
import hashlib

# CONFIGURACIÓN DE API KEYS
API_KEYS = {
    'virustotal': '536ddb2b38a9c4debd707085697b7c161eab72cb8f7aeed873af20711f08633b',
    'hybrid_analysis': 's68zidaddb865ee97zwp0p4s3ea18076obru272cef247e59v7xdx1is011adae3'
}

# calcular hashes MD5/SHA1/SHA256
def get_file_hashes(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            sha1_hash.update(byte_block)
            sha256_hash.update(byte_block)

    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()

# VIRUSTOTAL: espera resultado consultando el reporte por resource/scan_id
def esperar_resultado_virustotal(resource, max_espera=300, intervalo=60):
    tiempo_inicio = time.time()
    url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEYS['virustotal'], 'resource': resource}

    while (time.time() - tiempo_inicio) < max_espera:
        try:
            response = requests.get(url_report, params=params, verify=False)
            result = response.json()
        except Exception as e:
            print("Error consultando VirusTotal:", e)
            result = {}

        # response_code == 1 indica que hay resultado
        if result.get("response_code") == 1:
            return result

        print(f"Esperando resultado de VirusTotal... ({int(time.time() - tiempo_inicio)}s)")
        time.sleep(intervalo)

    return {'verbose_msg': 'Tiempo de espera agotado', 'positives': 'N/A'}

# HYBRID ANALYSIS: subir y obtener threat_score se omitio el analisis de tipo url no esta disponible
def analizar_hybrid_analysis(muestra, tipo):
    # url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
    if tipo == 'url':
        print("Hybrid Analysis no aplica para URL (ignorado)")
        return "NO_APLICA"

    #base_url_file = "https://www.hybrid-analysis.com/api/v2/submit/file"

    headers = {
        "api-key": API_KEYS['hybrid_analysis'],
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json"
    }

    try:
        with open(muestra, 'rb') as f:
            files = {'file': f}
            url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
            data = {'environment_id': '160'}
            resp = requests.post(url, headers=headers, files=files, data=data, verify=False)

        resp.raise_for_status()
        j = resp.json()
        return j.get("threat_score", "N/A")

    except Exception as e:
        print("Error Hybrid Analysis:", e)
        return "ERROR"

# Función principal que analiza muestra
def analizar_muestra(muestra, tipo):
    resultados = {}

    # si es archivo
    if tipo == 'archivo':
        if not os.path.isfile(muestra):
            print(f"Archivo no encontrado: {muestra}")
            resultados['MD5'] = resultados['SHA1'] = resultados['SHA256'] = 'NO_ENCONTRADO'
        else:
            md5, sha1, sha256 = get_file_hashes(muestra)
            resultados['MD5'] = md5
            resultados['SHA1'] = sha1
            resultados['SHA256'] = sha256
    else:
        resultados['MD5'] = resultados['SHA1'] = resultados['SHA256'] = ''

    # VIRUSTOTAL
    print("\n=== VIRUSTOTAL ===")
    vt_positives = 'N/A'
    try:
        if tipo == 'archivo' and os.path.isfile(muestra):
            # subir archivo para escaneo
            url_upload = "https://www.virustotal.com/vtapi/v2/file/scan"
            with open(muestra, 'rb') as fh:
                files = {'file': fh}
                params = {'apikey': API_KEYS['virustotal']}
                upload_response = requests.post(url_upload, files=files, params=params, verify=False, timeout=60).json()
                resource = upload_response.get('resource') or resultados.get('SHA256')
        else:
            # URL scan
            url_scan = "https://www.virustotal.com/vtapi/v2/url/scan"
            params = {'apikey': API_KEYS['virustotal'], 'url': muestra}
            scan_response = requests.post(url_scan, params=params, verify=False).json()
            resource = scan_response.get('scan_id') or scan_response.get('resource')

        # esperar/consultar resultado
        vt_resultado = esperar_resultado_virustotal(resource)
        vt_positives = vt_resultado.get('positives', 'N/A')
    except Exception as e:
        print("Error VirusTotal:", e)
        vt_positives = "ERROR"

    resultados['VirusTotal_positives'] = vt_positives
    time.sleep(10)  # espaciar peticiones para evitar límites

    # HYBRID ANALYSIS no realizamos el analisis por url no esta disponible paln free
    if tipo == "archivo":
        print("\n=== HYBRID ANALYSIS ===")
        ha_score = analizar_hybrid_analysis(muestra, tipo)
        time.sleep(10)
    else:
        print("\n=== HYBRID ANALYSIS === (NO APLICA PARA URL)")
        ha_score = "NO_APLICA"

    resultados['HybridAnalysis_threat_score'] = ha_score

    return resultados

# Generar reporte Excel con todos los resultados
def generar_reporte(resultados):
    if not resultados:
        print("No hay resultados para guardar.")
        return
    df = pd.DataFrame(resultados)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reportes", exist_ok=True)
    filename = os.path.join("reportes", f"reporte_{timestamp}.xlsx")
    df.to_excel(filename, index=False)
    print(f"\n Reporte generado: {filename}")

# MAIN: leer input/muestras.xlsx y procesar cada fila
def main():
    input_path = os.path.join("input", "muestras.xlsx")
    if not os.path.isfile(input_path):
        print(f"No existe el archivo de muestras: {input_path}")
        return

    df = pd.read_excel(input_path)

    resultados = []
    for _, row in df.iterrows():
        ruta = str(row.get("ruta", "")).strip()
        tipo = str(row.get("tipo", "")).strip().lower()
        if not ruta or tipo not in ('archivo', 'url'):
            print("Fila con formato inválido, se salta:", row.to_dict())
            continue

        print(f"\n Analizando: {ruta}  (tipo: {tipo})")
        resultado = analizar_muestra(ruta, tipo)
        resultado['ruta'] = ruta
        resultado['tipo'] = tipo
        resultados.append(resultado)

    generar_reporte(resultados)

if __name__ == "__main__":
    main()
