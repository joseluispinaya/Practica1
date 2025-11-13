import requests
import json
import pandas as pd
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import os
import hashlib

API_KEYS = {
    'virustotal': 'API_KEY',
    'hybrid-analysis': 'API_KEY'
}

def esperar_resultado_virustotal(resource, max_espera=300, intervalo=60):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEYS['virustotal'], 'resource': resource}

    tiempo_inicio = time.time()
    while (time.time() - tiempo_inicio) < max_espera:
        result = requests.get(url, params=params, verify=False).json()

        if result['response_code'] == 1:
            return result

        print(f"Esperando resultado de VirusTotal... ({int(time.time() - tiempo_inicio)} segundos)")
        time.sleep(intervalo)

    return {'verbose_msg': 'Tiempo de espera agotado', 'positives': 'N/A'}

# Calcula hashes MD5 / SHA1 / SHA256
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

def analizar_muestra(muestra, tipo):
    resultados = {}

    # Calcular hashes
    if tipo == 'archivo':
        md5, sha1, sha256 = get_file_hashes(muestra)
        resultados['MD5'] = md5
        resultados['SHA1'] = sha1
        resultados['SHA256'] = sha256
    else:
        resultados['MD5'] = ''
        resultados['SHA1'] = ''
        resultados['SHA256'] = ''

    # VirusTotal (4 peticiones por minuto en versión gratuita)
    if tipo == 'archivo':
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': API_KEYS['virustotal'], 'resource': resultados['SHA256']}
    else:
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': API_KEYS['virustotal'], 'resource': muestra}

    response = requests.get(url, params=params, verify=False)
    vt_result = response.json()
    print("VIRUSTOTAL: " + str(vt_result))

    # Si el archivo no ha sido analizado previamente 
    if vt_result['response_code'] == 0:
        if tipo == 'archivo':
            upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            files = {'file': (os.path.basename(muestra), open(muestra, 'rb'))}
            upload_response = requests.post(upload_url, files=files, params={'apikey': API_KEYS['virustotal']}, verify=False)
            upload_result = upload_response.json()
            print("VIRUSTOTAL Upload: " + str(upload_result))
            vt_result = esperar_resultado_virustotal(upload_result['resource'])
        else:
            scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': API_KEYS['virustotal'], 'url': muestra}
            scan_response = requests.post(scan_url, data=params, verify=False)
            scan_result = scan_response.json()
            print("VIRUSTOTAL URL Scan: " + str(scan_result))
            vt_result = esperar_resultado_virustotal(scan_result['scan_id'])

    resultados['virustotal'] = vt_result.get('positives', 'N/A')
    resultados['vt_mensaje'] = vt_result.get('verbose_msg', '')
    time.sleep(15)  # Esperar 15 segundos entre peticiones

    # Hybrid Analysis 'https://www.hybrid-analysis.com/api/v2/submit/url'
    if tipo == 'archivo':
        url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
        files = {'file': open(muestra, 'rb')}
        data = {'environment_id': '160'}
    else:
        url = 'https://www.hybrid-analysis.com/api/v2/submit/url'
        files = None
        data = {'url': muestra, 'environment_id': '160'}

    headers = {"api-key": API_KEYS['hybrid-analysis']}
    response = requests.post(url, headers=headers, files=files, data=data, verify=False)
    ha_result = response.json()
    print("HYBRID: " + str(ha_result))
    resultados['hybrid-analysis'] = ha_result.get("threat_score", 0)
    time.sleep(30)  # response = requests.post(url, headers=headers, files=files, data=data, verify=False)

    return resultados

def generar_reporte(resultados):
    df = pd.DataFrame(resultados)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reporte_analisis_{timestamp}.xlsx"
    df.to_excel(filename, index=False)
    print(f"\n Reporte generado ({filename})")

def main():
    # Leer muestras desde un archivo Excel muestras.xlsx
    df_muestras = pd.read_excel("muestras.xlsx")

    resultados = []
    for _, row in df_muestras.iterrows():
        resultado = analizar_muestra(row['ruta'], row['tipo'])
        resultado['muestra'] = row['ruta']
        resultado['tipo'] = row['tipo']
        resultados.append(resultado)

    generar_reporte(resultados)

if __name__ == "__main__":
    main()