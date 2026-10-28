# WebSentinel-CS :: Enterprise Security Operations & Telemetry Sentinel

[![Node.js Engine](https://img.shields.io/badge/Node.js-v18%2B-22c55e?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Laravel Integration](https://img.shields.io/badge/Laravel-10%20%7C%2011%20Ready-FF2D20?logo=laravel&logoColor=white)](integrations/laravel/)
[![Database Engine](https://img.shields.io/badge/Database-SQLite%20(Native%20SQL)-003B57?logo=sqlite&logoColor=white)](data/)
[![License: MIT](https://img.shields.io/badge/License-MIT-3b82f6.svg)](LICENSE)
[![Standards Compliance](https://img.shields.io/badge/Standard-OWASP%20Top%2010%20%7C%20CWE-0f172a)](https://owasp.org/)
[![Dependency Footprint](https://img.shields.io/badge/Dependencies-0%20(Pure%20Native%20Runtime)-059669)](package.json)

**WebSentinel-CS** es una plataforma centinela, consola de operaciones de seguridad (SOC) y paquete de protección WAF para aplicaciones **Node.js, Laravel (PHP) y motores SQL**, desarrollada para la auditoría continua de postura, mitigación de ataques de fuerza bruta y análisis heurístico de peticiones web en tiempo real.

---

## 🚀 Ecosistema Multitecnología: Node.js + SQL + Laravel

* **Daemon Central (Node.js & SQLite):** Motor de alta velocidad (<80ms) con almacenamiento de incidentes persistente en base de datos SQL (`sentinel.sqlite`) y panel de control web.
* **Paquete de Middleware para Laravel (`integrations/laravel/`):** Middleware WAF desacoplado que intercepta peticiones en aplicaciones Laravel 10/11, bloquea inyecciones SQL/XSS antes de tocar controladores y emite telemetría al centinela.
* **Consola Forense SQL:** Permite a analistas ejecutar consultas SQL analíticas directamente desde la interfaz web.

---

## 🏛️ Arquitectura del Sistema

```
                      +------------------------------------------+
                      |         WEBSENTINEL-CS ENGINE            |
                      +------------------------------------------+
                                           |
         +---------------------------------+---------------------------------+
         |                                 |                                 |
         v                                 v                                 v
+------------------+             +-------------------+             +-------------------+
|  POSTURE AUDIT   |             |  RATE LIMIT ENGINE|             | HEURISTIC WAF     |
|  - OWASP Headers |             |  - Sliding Window |             | - CWE-89 (SQLi)   |
|  - Latency / SLA |             |  - IP Cooldown    |             | - CWE-79 (XSS)    |
|  - Exposure Scan |             |  - Auth Anomaly   |             | - CWE-22 (LFI)    |
+------------------+             +-------------------+             +-------------------+
         |                                 |                                 |
         +---------------------------------+---------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |     STRUCTURED TELEMETRY & SOC STREAM    |
                      |   (Real-time Audit Log & CSV Exporter)   |
                      +------------------------------------------+
```

---

## 🛡️ Capacidades del Motor de Seguridad

### 1. Auditoría de Postura y Cumplimiento OWASP
* Evaluación activa de cabeceras de transporte y contención:
  * `Content-Security-Policy` (CSP)
  * `X-Frame-Options` (Mitigación de Clickjacking)
  * `X-Content-Type-Options` (Prevención de MIME-Sniffing)
  * `Strict-Transport-Security` (Garantía HSTS)
  * `Referrer-Policy` (Privacidad de metadatos)
* Cálculo automático de índice de blindaje y diagnóstico de latencia.

### 2. Mitigación de Fuerza Bruta por Ventana Deslizante (CWE-799)
* Evaluación probabilística y determinista de intentos de autenticación fallidos por dirección IP en ventanas de 60 segundos.
* Asignación inmediata de estado `IP_BLOCKED` con período de enfriamiento (*cooldown*) dinámico.

### 3. Motor Heurístico de Inspección de Payloads
* Análisis de firmas contra las principales clasificaciones de debilidades comunes:
  * **CWE-89:** Inyección SQL (Tautologías lógicas, cláusulas `UNION SELECT`, comentarios de escape `--`).
  * **CWE-79:** Cross-Site Scripting (Inyecciones de script explícitas, manejadores de eventos inline, esquemas de pseudocódigo).
  * **CWE-22:** Path Traversal / LFI (Secuencias de escalado de directorios `../` e intentos de lectura de configuración).
* **Verificación de Honeypot:** Detección de rastreadores y bots automatizados mediante señuelos sintéticos en formularios.

### 4. Telemetría Estructurada & Consola SOC
* Tabulación forense de eventos con identificadores únicos (`SEC-XXXX`), sello temporal UTC, IP origen, endpoint objetivo y acción ejecutada.
* Exportación estructurada a formato **CSV** para ingesta en sistemas SIEM perimetrales.

---

## ⚡ Especificaciones Técnicas y Rendimiento

* **Runtime:** Node.js v18.0.0+ (ES2022).
* **Dependencias de terceros:** **0 (Cero)**. Construido íntegramente sobre módulos nativos (`http`, `https`, `crypto`, `fs`, `url`, `path`).
* **Tiempo de inicialización:** < 80 ms.
* **Huella de memoria:** ~28 MB RSS.

---

## 🚀 Inicio Rápido

### Ejecución Local

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/Holasoyandres/WebSentinel-CS.git
   cd WebSentinel-CS
   ```

2. Arrancar el motor centinela:
   ```bash
   npm start
   ```
   *(En Windows puede ejecutarse directamente mediante el script `iniciar_centinela.bat`)*

3. Abrir la consola de control en el navegador:
   ```
   http://localhost:4000
   ```

---

## 📡 Endpoints de la API de Telemetría

| Método | Ruta | Función |
| :--- | :--- | :--- |
| `GET` | `/api/stats` | Métricas operacionales y estado del motor. |
| `GET` | `/api/events` | Búfer circular de eventos de telemetría. |
| `GET` | `/api/export-csv` | Descarga de registro forense en formato CSV. |
| `POST` | `/api/scan` | Ejecuta auditoría remota sobre una URL objetivo. |
| `POST` | `/api/analyze-request` | Inspección heurística de cadenas y honeypots. |
| `POST` | `/api/record-login` | Registro de intentos de autenticación y cálculo de rate limiting. |

---

## 👤 Autor

* **Holasoyandres**
* Repositorio: [@Holasoyandres/WebSentinel-CS](https://github.com/Holasoyandres/WebSentinel-CS)

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulte el archivo [LICENSE](LICENSE) para más detalles.
