# 🛡️ WebSentinel-CS: Autonomous Web Security & Anomaly Detection Sentinel

[![Node.js Version](https://img.shields.io/badge/Node.js-v18%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Standard](https://img.shields.io/badge/Standard-OWASP%20Top%2010-critical)](https://owasp.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Pure%20Native)-success)](package.json)

**WebSentinel-CS** es una plataforma centinela y panel de control de ciberseguridad defensiva (SOC en miniatura) diseñado para auditar, monitorizar y proteger aplicaciones web, portales de atención ciudadana y APIs empresariales contra fraudes, ataques de fuerza bruta y explotación de vulnerabilidades web.

Desarrollado como un centinela **100% independiente (out-of-band)**: vigila y analiza el tráfico y estado de cualquier página sin modificar ni comprometer el código fuente de las aplicaciones en producción.

---

## 🚀 Características Principales

```
+---------------------------------------------------------------------------------+
|                                WEBSENTINEL-CS                                   |
|   +--------------------+  +----------------------+  +-----------------------+   |
|   |   Auditor de URL   |  |  Detector de Fuerza  |  |  Inspector Profundo   |   |
|   |  y Cabeceras OWASP |  |   Bruta y Fraude     |  |   de Formularios      |   |
|   +--------------------+  +----------------------+  +-----------------------+   |
|             |                        |                          |               |
|             v                        v                          v               |
|   +-------------------------------------------------------------------------+   |
|   |           Motor de Reglas y Telemetría en Tiempo Real (SOC Stream)      |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
```

### 1. 🌐 Auditor de Seguridad de URLs & Blindaje OWASP
* Escaneo activo y pasivo de endpoints para evaluar el cumplimiento de cabeceras críticas:
  * `Content-Security-Policy` (CSP)
  * `X-Frame-Options` (Anti-Clickjacking)
  * `X-Content-Type-Options` (MIME-Sniffing Prevention)
  * `Strict-Transport-Security` (HSTS)
  * `Referrer-Policy`
* Medición de latencia de red y detección de fallos de servidor (códigos HTTP anómalos `500`, `502`).

### 2. 🔒 Detección Adaptativa de Fuerza Bruta (Sliding-Window Rate Limiter)
* Algoritmo de ventana deslizante en memoria que calcula los intentos fallidos de autenticación por dirección IP en ventanas de 60 segundos.
* Bloqueo y enfriamiento temporal automático ante ráfagas de inicio de sesión o ataques de diccionario.

### 3. 🧪 Inspección Profunda de Payloads & Trampa Bot (Honeypot)
* **Motor de firmas heurísticas:** Detecta intentos de:
  * Inyección SQL (Tautologías `' OR 1=1`, `UNION SELECT`, Comentarios `--`).
  * Cross-Site Scripting (XSS reflectivo, tags `<script>`, manejadores de eventos en línea).
  * Path Traversal (`../`, escalado de directorios hacia archivos sensibles).
* **Verificación de Honeypot:** Detección de rastreadores y bots automáticos mediante campos trampa invisibles para usuarios legítimos.

### 4. 📡 Dashboard Visual & Telemetría en Tiempo Real (Cyber SOC UI)
* Interfaz oscura moderna con diseño de Centro de Operaciones de Seguridad (SOC).
* Flujo dinámico de eventos clasificados por severidad (`CRITICAL`, `DANGER`, `WARNING`, `INFO`).
* Simulador interactivo de vectores de ataque para demostraciones en vivo.

---

## 📦 Filosofía de Diseño: Cero Dependencias

Para garantizar máxima portabilidad, velocidad y seguridad, **WebSentinel-CS no requiere paquetes externos de `npm`**. Funciona exclusivamente con las APIs nativas de Node.js (`http`, `https`, `crypto`, `fs`, `url`, `path`), lo que garantiza:
- **0 vulnerabilidades en la cadena de suministro** (sin riesgo de paquetes comprometidos en `node_modules`).
- **Arranque instantáneo (< 100 ms).**
- **100% portable y autónomo.**

---

## ⚡ Instalación y Uso Rápido

### Requisitos
* [Node.js](https://nodejs.org/) (versión 18 o superior).

### Ejecución en 1 Paso

1. Clona el repositorio:
   ```bash
   git clone https://github.com/Holasoyandres/WebSentinel-CS.git
   cd WebSentinel-CS
   ```

2. Inicia el centinela:
   ```bash
   npm start
   ```
   *(En Windows también puedes hacer doble clic en `iniciar_centinela.bat`)*

3. Abre tu navegador en:
   ```
   http://localhost:4000
   ```

---

## 🛠️ API REST de Integración Externa

Cualquier sistema externo o webhook puede enviar eventos o validar entradas consumiendo los endpoints del centinela:

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/stats` | Métricas globales de incidentes y tiempo de actividad. |
| `GET` | `/api/events` | Flujo de eventos de seguridad registrados. |
| `POST` | `/api/scan` | Audita las cabeceras y seguridad de una URL objetivo. |
| `POST` | `/api/analyze-request` | Inspecciona cadenas y valida campos honeypot. |
| `POST` | `/api/record-login` | Registra intentos de login y evalúa rate limiting. |

---

## 👤 Autor

* **Holasoyandres** - *Desarrollo y Arquitectura de Ciberseguridad Defensiva*
* GitHub: [@Holasoyandres](https://github.com/Holasoyandres)

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
