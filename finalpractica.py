import pandas as pd
import requests
import re
import tldextract
import difflib
from urllib.parse import urlparse
from openpyxl import Workbook
import xml.etree.ElementTree as ET


# ============================================
# 1. ANALISIS HEURISTICO LOCAL (IA SIMPLE)
# ============================================

def extraer_caracteristicas(url):
    car = {}

    car["longitud"] = len(url)
    car["num_guiones"] = url.count("-")
    car["num_arrobas"] = url.count("@")
    car["num_puntos"] = url.count(".")
    car["num_slash"] = url.count("/")

    # Detectar si usa IP
    car["usa_ip"] = bool(re.match(r"(http[s]?://)?\d{1,3}(?:\.\d{1,3}){3}", url))

    # Partes del dominio
    ext = tldextract.extract(url)
    dominio = ext.domain.lower()
    car["dominio"] = dominio
    subdominios = ext.subdomain

    # Demasiados subdominios = sospechoso
    car["subdominios_sospechosos"] = len(subdominios.split(".")) > 2

    # Palabras típicas de phishing
    palabras_phish = ["login", "secure", "account", "verify", "update", "bank"]
    car["palabra_sospechosa"] = any(p in url.lower() for p in palabras_phish)

    # -----------------------------------------
    # Typosquatting (imitación de marcas reales)
    # -----------------------------------------
    targets = ["paypal", "google", "facebook", "netflix", "apple", "microsoft", "amazon", "github"]

    car["typosquatting"] = False
    for t in targets:
        similitud = difflib.SequenceMatcher(None, dominio, t).ratio()
        if similitud > 0.6 and dominio != t:
            car["typosquatting"] = True
            break

    # -----------------------------------------
    # Hosting gratuito (muy común en phishing)
    # -----------------------------------------
    hostings = ["weebly", "wixsite", "000webhostapp", "blogspot", "wordpress"]
    car["hosting_gratuito"] = any(h in url.lower() for h in hostings)

    return car


def clasificar_heuristica(car):

    score = 0
    if car["longitud"] > 80:
        score += 1
    if car["num_guiones"] > 3:
        score += 1
    if car["num_slash"] > 7:
        score += 1
    if car["usa_ip"]:
        score += 2
    if car["subdominios_sospechosos"]:
        score += 1
    if car["palabra_sospechosa"]:
        score += 2
    if car["typosquatting"]:
        score += 3
    if car["hosting_gratuito"]:
        score += 2

    if score >= 6:
        return "SOSPECHA ALTA"
    elif score >= 3:
        return "SOSPECHA MEDIA"
    else:
        return "NORMAL"


# ============================================
# 2. CONSULTA A PHISHTANK (SERVICIO EXTERNO)
# ============================================

def consultar_phishtank(url):
    api_url = "https://checkurl.phishtank.com/checkurl/"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    data = {
        "format": "xml",
        "url": url
    }

    try:
        resp = requests.post(api_url, headers=headers, data=data, timeout=10)

        # Si PhishTank devuelve HTML → error
        if not resp.text.startswith("<?xml"):
            return "NO REPORTADO / API LIMITADA"

        xml_resp = ET.fromstring(resp.text)

        in_db_node = xml_resp.find(".//in_database")
        valid_node = xml_resp.find(".//valid")

        if in_db_node is None or valid_node is None:
            return "NO REPORTADO / API LIMITADA"

        in_db = in_db_node.text
        valid = valid_node.text

        if in_db == "true" and valid == "true":
            return "PHISHING CONFIRMADO"
        elif in_db == "true" and valid == "false":
            return "REPORTADO / EN REVISION"
        else:
            return "NO REPORTADO"

    except Exception as e:
        return "ERROR API"


# ============================================
# 3. LECTURA, ANALISIS Y EXPORTACION
# ============================================

def analizar_archivo_excel(ruta_excel):

    df = pd.read_excel(ruta_excel)
    urls = df.iloc[1:, 0].tolist()  # Saltamos A1 ("phish")

    resultados = []

    for url in urls:
        url = str(url)
        print(f" Analizando: {url}")

        # Heurística
        car = extraer_caracteristicas(url)
        heuristica = clasificar_heuristica(car)

        # Servicio externo
        phishtank = consultar_phishtank(url)

        # Clasificación final combinada
        if phishtank == "PHISHING CONFIRMADO":
            final = "PHISHING"
        elif phishtank == "REPORTADO / EN REVISION":
            final = "SOSPECHOSA"
        elif heuristica in ["SOSPECHA MEDIA", "SOSPECHA ALTA"]:
            final = "SOSPECHOSA"
        else:
            final = "NORMAL"

        fila = {
            "URL": url,
            "Dominio": car["dominio"],
            "Longitud": car["longitud"],
            "Guiones": car["num_guiones"],
            "Arrobas": car["num_arrobas"],
            "Slashes": car["num_slash"],
            "Usa_IP": car["usa_ip"],
            "Subdominios_sospechosos": car["subdominios_sospechosos"],
            "Palabras_sospechosas": car["palabra_sospechosa"],
            "Typosquatting": car["typosquatting"],
            "Hosting_gratuito": car["hosting_gratuito"],
            "Heuristica": heuristica,
            "PhishTank": phishtank,
            "Clasificacion_Final": final
        }

        resultados.append(fila)

    return resultados


def generar_excel(resultados, output_path="resulscan.xlsx"):

    wb = Workbook()
    ws = wb.active
    ws.title = "Phishing Scan"

    ws.append([
        "URL", "Dominio", "Longitud", "Guiones", "Arrobas", "Slashes",
        "Usa_IP", "Subdominios_sospechosos", "Palabras_sospechosas",
        "Typosquatting", "Hosting_gratuito",
        "Heuristica", "PhishTank", "Clasificacion_Final"
    ])

    for r in resultados:
        ws.append([
            r["URL"], r["Dominio"], r["Longitud"], r["Guiones"], r["Arrobas"],
            r["Slashes"], r["Usa_IP"], r["Subdominios_sospechosos"],
            r["Palabras_sospechosas"], r["Typosquatting"],
            r["Hosting_gratuito"], r["Heuristica"],
            r["PhishTank"], r["Clasificacion_Final"]
        ])

    wb.save(output_path)
    print(f"\n Archivo Excel generado: {output_path}")


if __name__ == "__main__":
    print(" Iniciando análisis de URLs (IA + PhishTank)...\n")
    resultados = analizar_archivo_excel("posiblesphis.xlsx")
    generar_excel(resultados)
    print("\n Análisis completado.")
