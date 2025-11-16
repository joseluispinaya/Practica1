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

API_KEY_SAFEBROWSING = "API_KEY"
API_KEY_VIRUSTOTAL = "API_KEY"
API_KEY_URLSCAN = "API_KEY"


# =============================================
#        GOOGLE SAFE BROWSING (GSB)
# =============================================

def consultar_safebrowsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_SAFEBROWSING}"

    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(api_url, json=payload, timeout=12)
        data = resp.json()

        if "matches" in data:
            return "PHISHING CONFIRMADO"

        return "NO REPORTADO"

    except Exception as e:
        return f"ERROR → {e}"



# =============================================
#             VIRUSTOTAL (URL)
# =============================================

def consultar_virustotal(url):
    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"

    params = {
        "apikey": API_KEY_VIRUSTOTAL,
        "resource": url
    }

    try:
        resp = requests.get(endpoint, params=params, timeout=12)
        data = resp.json()

        if data.get("response_code") == 1:
            pos = data.get("positives", 0)
            return f"{pos} detecciones"

        return "NO REPORTADO"

    except Exception as e:
        return f"ERROR → {e}"



# =============================================
#                URLSCAN.IO
# =============================================

def urlscan_submit(url, visibility="public", country=None, tags=None, timeout=15):
    endpoint = "https://urlscan.io/api/v1/scan/"

    headers = {
        "API-Key": API_KEY_URLSCAN,
        "Content-Type": "application/json",
        "User-Agent": "phishing-detector/1.0"
    }

    payload = {"url": url, "visibility": visibility}
    if country:
        payload["country"] = country
    if tags:
        payload["tags"] = tags

    resp = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)

    print("\n===== URLSCAN.IO SUBMIT =====")
    print("[DEBUG] Status:", resp.status_code)
    print("[DEBUG] Respuesta:", resp.text)

    if resp.status_code not in (200, 201):
        return None, resp.status_code, resp.text

    j = resp.json()
    uuid = j.get("uuid")
    return uuid, resp.status_code, j



def urlscan_get_result(uuid, retries=12, wait=5, timeout=15):
    if not uuid:
        return None, "no-uuid"

    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"

    headers = {
        "API-Key": API_KEY_URLSCAN,
        "User-Agent": "phishing-detector/1.0",
        "Accept": "application/json"
    }

    print("\n===== URLSCAN.IO POLLING =====")

    for attempt in range(1, retries + 1):
        resp = requests.get(result_url, headers=headers, timeout=timeout)
        print(f"[DEBUG] Intento {attempt}, status:", resp.status_code)

        if resp.status_code == 200:
            print("[DEBUG] Resultado obtenido")
            return resp.json(), None

        if resp.status_code == 404:  # aún no está listo
            print(f"[DEBUG] No disponible (404). Esperando {wait}s...")
            time.sleep(wait)
            continue

        print("[DEBUG] Error en polling:", resp.text)
        return None, f"error_status_{resp.status_code}"

    return None, "timeout"



def consultar_urlscan(url):
    uuid, status_code, submit_data = urlscan_submit(url)

    if not uuid:
        return f"ERROR AL ENVIAR (status={status_code})"

    print(f"[INFO] Scan enviado. UUID = {uuid}")

    result_json, err = urlscan_get_result(uuid)

    if err is not None:
        return f"NO REPORTADO ({err})"

    verdicts = result_json.get("verdicts", {})
    overall = verdicts.get("overall", {})

    malicious = overall.get("malicious", False)
    score = overall.get("score", None)

    if malicious:
        return f"Malicioso (score={score})"
    # return f"Malicioso (score={score}) uuid={uuid}"

    if score:
        return f"No claramente malicioso (score={score})"
    # return f"No claramente malicioso (score={score}) uuid={uuid}"

    return f"NO REPORTADO"
# return f"NO REPORTADO uuid={uuid}"


# =============================================
#           CONSOLA UNIFICADA Elzero2025@
# =============================================

def analizar_url(url):
    print("\n====================================")
    print("       ANÁLISIS DE URL (3 APIs)")
    print("====================================")
    print(f"URL: {url}\n")

    gsb = consultar_safebrowsing(url)
    vt  = consultar_virustotal(url)
    us  = consultar_urlscan(url)

    print("\n========= RESULTADOS =========")
    print(f"[GSAFE]         → {gsb}")
    print(f"[VIRUSTOTAL]    → {vt}")
    print(f"[URLSCAN.IO]    → {us}")
    print("====================================\n")


# =============================================
#                PROGRAMA
# =============================================

if __name__ == "__main__":
    url_test = "https://uphitoldlogin.gitbook.io/sign-in/"
    analizar_url(url_test)
