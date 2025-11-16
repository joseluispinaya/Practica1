
# Proyecto de Análisis de Malware  
Automatización mediante análisis estático y uso de APIs de Inteligencia Antivirus (VirusTotal & Hybrid Analysis)

## Descripción del Proyecto
Este proyecto automatiza el proceso de análisis de archivos ejecutables utilizando técnicas de análisis estático y servicios basados en inteligencia artificial, como:

- **VirusTotal** → detección por múltiples motores antivirus  
- **Hybrid Analysis** → análisis avanzados con IA y threat scoring  

El sistema procesa archivos o URLs indicados en un Excel, extrae características estáticas, consulta los servicios de análisis y genera un reporte final consolidado en formato Excel.

---

## Funcionalidades Principales

✔ Extracción de hashes estáticos (MD5, SHA1, SHA256)  
✔ Análisis automático con VirusTotal  
✔ Análisis de threat score con Hybrid Analysis  
✔ Espera activa para obtener resultados completos  
✔ Clasificación automática (malicioso, sospechoso, benigno)  
✔ Generación automática de reportes Excel  
✔ Soporte para análisis de URLs y archivos  

---

## Estructura del Proyecto

```
DIPLOMADO/
│── input/                 # Muestras a analizar (muestras.xlsx)
│── reportes/              # Reportes generados automáticamente
│── venv/                  # Entorno virtual (IGNORADO en Git)
│── analisis_malware.py    # Versión prueba 1
│── analisisfin.py         # Versión prueba 2
│── analisiszero.py        # Versión principal del analizador
│── muestras.xlsx          # Archivo de entrada prueba
│── README.md
```

---

## ¿Cómo funciona el análisis?

1. El sistema lee `input/muestras.xlsx`, que contiene:
   - Ruta del archivo y URL  
   - Tipo (`archivo` y `url`)  

2. Si es archivo:
   - Calcula MD5, SHA1, SHA256  
   - Lo envía a VirusTotal  
   - Lo envía a Hybrid Analysis  

3. Si es URL:
   - Analiza exclusivamente en VirusTotal omite Hybrid Analysis

4. Consolida toda la información en un Excel dentro de la carpeta `/reportes`.

---

## Requisitos

Asegúrate de tener Python 3.8 o superior.

Instala las dependencias:

```bash
pip install -r requirements.txt
```

---

## Configuración de API Keys

En el script principal se deben colocar las claves:

```python
API_KEYS = {
    'virustotal': 'TU_API_KEY_AQUI',
    'hybrid_analysis': 'TU_API_KEY_AQUI'
}
```

---

## Cómo Ejecutar el Proyecto

1. Activa tu entorno virtual

2. Ejecuta el script:

```bash
python analisiszero.py
```

3. Revisa tu reporte en:

```
/reportes/reporte_YYYYMMDD_HHMMSS.xlsx
```

---

## Formato del archivo de entrada

El archivo `muestras.xlsx` debe contener como mínimo estas columnas:

| tipo         | ruta                     |
|--------------|--------------------------|
| url          | https://szunioncargo.com |
| archivo      | 20666bbfef174ca5.js      |

---

## Info

1. Practica 1 Ejecutar:

```bash
python analisiszero.py
```

2. Practica 2 Ejecutar:

```bash
python analisisamenaza.py
```

3. Practica 3 Ejecutar:

```bash
python analisispishin.py
```
