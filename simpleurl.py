
import pandas as pd
import requests
import re
import tldextract
import difflib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#from urllib.parse import urlparse
#from openpyxl import Workbook
import time

API_KEY_SAFEBROWSING = "AIzaSyBX3UelHbndIsc2VQYILu-KfOVaW-SXEY0"
API_KEY_VIRUSTOTAL = "536ddb2b38a9c4debd707085697b7c161eab72cb8f7aeed873af20711f08633b"
API_KEY_HYBRID = "s68zidaddb865ee97zwp0p4s3ea18076obru272cef247e59v7xdx1is011adae3"

def consultar_safebrowsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_SAFEBROWSING}"

    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        resp = requests.post(api_url, json=payload, timeout=10)
        print("\n===== GOOGLE SAFE BROWSING =====")

        print(f"[DEBUG] Status Code: {resp.status_code}")
        # print(f"[DEBUG] Respuesta JSON: {resp.text}")

        data = resp.json()

        if "matches" in data:
            return "PHISHING CONFIRMADO"
        else:
            return "NO REPORTADO"

    except Exception as e:
        # print(f"[ERROR] {e}")
        return f"ERROR API → {e}"

# ============================
#  VIRUSTOTAL (URL)
# ============================

def consultar_virustotal(url):
    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"

    params = {
        "apikey": API_KEY_VIRUSTOTAL,
        "resource": url
    }

    try:
        resp = requests.get(endpoint, params=params)
        print("\n===== VIRUSTOTAL =====")
        print("[DEBUG] Status:", resp.status_code)
        # print("[DEBUG] Respuesta:", resp.text)

        data = resp.json()

        # response_code = 1 → URL encontrada
        if data.get("response_code") == 1:
            positives = data.get("positives", 0)
            return f"Detecciones: {positives}"
        else:
            return "NO REPORTADO"

    except Exception as e:
        return f"ERROR API → {e}"


# ============================
#  HYBRID ANALYSIS (URL)
# ============================

def consultar_hybrid_analysis(url):
    endpoint = "https://www.hybrid-analysis.com/api/v2/submit/url"
    files = None

    headers = {"api-key": API_KEY_HYBRID}

    data = {
        "url": url,
        "environment_id": "160"     # Windows 7 64-bit
    }

    try:
        resp = requests.post(endpoint, headers=headers, files=files, data=data, verify=False)
        print("\n===== HYBRID ANALYSIS =====")
        print("[DEBUG] Status:", resp.status_code)
        print("[DEBUG] Respuesta:", resp.text)

        data = resp.json()
        threat = data.get("threat_score", None)

        if threat is None:
            return "NO REPORTADO"

        return f"Threat Score: {threat}"

    except Exception as e:
        return f"ERROR API → {e}"


# ============================
#  PROGRAMA PRINCIPAL
# ============================

if __name__ == "__main__":
    url_test = "https://uphitoldlogin.gitbook.io/sign-in/"

    print("\n==============================")
    print(" ANALISIS DE URL (3 SERVICIOS)")
    print("==============================")
    print(f"URL: {url_test}")

    #resultado_gsb = consultar_safebrowsing(url_test)
    #resultado_vt  = consultar_virustotal(url_test)
    resultado_ha  = consultar_hybrid_analysis(url_test)

    print("\n======= RESULTADOS =======")
    #print("Google Safe Browsing →", resultado_gsb)
    #print("VirusTotal →", resultado_vt)
    print("Hybrid Analysis →", resultado_ha)

    print("\n Análisis completado.\n")
