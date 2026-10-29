# WebSentinel-CS :: Enterprise Security Operations & Telemetry Sentinel

[![Node.js Engine](https://img.shields.io/badge/Node.js-v20%2B%20%7C%20v22%20%7C%20v24-22c55e?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Laravel Integration](https://img.shields.io/badge/Laravel-10%20%7C%2011%20%7C%2012%20Ready-FF2D20?logo=laravel&logoColor=white)](integrations/laravel/)
[![Database Engine](https://img.shields.io/badge/Database-SQLite%20(Native%20SQL)-003B57?logo=sqlite&logoColor=white)](data/)
[![License: MIT](https://img.shields.io/badge/License-MIT-3b82f6.svg)](LICENSE)
[![Standards Compliance](https://img.shields.io/badge/Standard-OWASP%20Top%2010%20%7C%20CWE-0f172a)](https://owasp.org/)
[![Dependency Footprint](https://img.shields.io/badge/Dependencies-0%20(Pure%20Native%20Runtime)-059669)](package.json)
[![Tests Passing](https://img.shields.io/badge/Tests-172%2F172%20Passing-success)](test/)

**WebSentinel-CS** es una plataforma centinela, consola de operaciones de seguridad (SOC) en tiempo real y cortafuegos de aplicaciones web (WAF) heurístico para ecosistemas **Node.js, Laravel (PHP) y bases de datos SQL**. Diseñada para inspección profunda de tráfico, detección de anomalías OWASP CRS, mitigación de fuerza bruta y auditoría forense con encadenamiento criptográfico SHA-256.

Construida con una filosofía de **cero dependencias externas en tiempo de ejecución (0 npm runtime dependencies)** utilizando exclusivamente módulos nativos de Node.js.

---

## 🌟 Características Principales

* 📡 **Streaming en Tiempo Real con Server-Sent Events (SSE)**: Conexión continua y ligera (`GET /api/v1/stream`) que reemplaza el polling tradicional. Indicador de estado en vivo, reconexión automática con *exponential backoff* y pulso de vida (*heartbeat*) cada 15 segundos.
* 🛡️ **WAF Heurístico con Pipeline de Normalización**:
  * Desofuscación recursiva de URL (hasta 3 niveles para neutralizar bypasses como `%2527`).
  * Decodificación de entidades HTML (`&quot;`, `&#x27;`, etc.).
  * Normalización Unicode (`NFKC`) y eliminación estricta de bytes nulos (`\0`).
  * Desactivación de comentarios SQL inline (`/* ... */`) y límite de seguridad contra ReDoS (16 KB).
* 🎯 **Fuente Única de Firmas y Anomaly Scoring OWASP**:
  * Repositorio centralizado en [`rules/signatures.json`](rules/signatures.json) (SQLi, XSS, Path Traversal / LFI, Command Injection).
  * Puntuación de anomalía acumulativa: `ALLOW` (0), `FLAG` (1–4), `BLOCK` ($\ge$ 5).
  * 0% de falsos positivos demostrados sobre textos benignos complejos en español.
* 🔐 **Seguridad en Profundidad & RBAC Estricto**:
  * **Roles en Consola**: `admin` (control total y consola SQL), `analyst` (escaneo, exportación y telemetría), `viewer` (solo lectura).
  * **Scopes en API Keys**: `ingest` (escritura de telemetría únicamente), `read` (lectura de métricas/stream), `admin` (gestión integral).
  * **Mitigación de Timing Attacks**: Ejecución sintética de `crypto.scrypt` en usuarios inexistentes para homogeneizar tiempos de respuesta.
* 🔗 **Forense con Cadena Criptográfica Inmutable**:
  * Cada incidente registrado se sella con un hash SHA-256 encadenado criptográficamente al evento anterior (`chain_hash`).
  * Verificación de integridad en tiempo real con auditoría de consistencia de bloques (`GET /api/v1/integrity/verify`).
* 📊 **Exportación Segura contra CSV / Formula Injection**:
  * Desarme automático de fórmulas maliciosas en celdas que inicien con `=`, `+`, `-`, `@`, `\t` o `\r`.
  * Filtros por rango de fechas (`?from=...&to=...`) y búsqueda textual.
* 🐘 **Paquete Oficial para Laravel 10/11/12 (`integrations/laravel`)**:
  * Middleware de firewall desacoplado con garantía **fail-open** (< 200 ms).
  * Despacho asíncrono fuera de banda mediante hooks del ciclo de vida de Laravel (`app()->terminating(...)`).
  * Listeners de autenticación para auditoría real de sesiones de usuario.
  * Componente Blade Honeypot inteligente con esteganografía CSS y sello temporal HMAC contra bots rápidos.
* 🛠️ **Panel Administrativo de Seguridad**:
  * Creación y revocación dinámica de API keys con selección granular de scopes.
  * Monitorización de IPs bloqueadas con tiempo restante y opción de desbloqueo manual auditado.

---

## 🏛️ Arquitectura del Sistema

```
                            +-----------------------------------------------+
                            |             CLIENTES PERIMETRALES             |
                            |   (Laravel Middleware / Microservicios / UI)  |
                            +-----------------------------------------------+
                                                    |
                                      POST /api/v1/events (X-Sentinel-Key)
                                                    v
+---------------------------------------------------------------------------------------------------+
|                                      WEBSENTINEL-CS DAEMON                                        |
|                                                                                                   |
|   +-----------------------+     +------------------------+     +------------------------------+   |
|   | NORMALIZATION PIPELINE|     |  SIGNATURE REPOSITORY  |     | RATE LIMIT & SLIDING WINDOW  |   |
|   | - Multi-pass URL Dec. | --> |  - OWASP Anomaly Score | --> | - Max 5 fallos / 15 min      |   |
|   | - Unicode NFKC & Null |     |  - Regex Anti-ReDoS    |     | - IP Cooldown Dinámico       |   |
|   +-----------------------+     +------------------------+     +------------------------------+   |
|                                              |                                                    |
|                                              v                                                    |
|                               +------------------------------+                                    |
|                               | SQLITE ENGINE (WAL + WAL2)   |                                    |
|                               | - Chained SHA-256 Hashing    |                                    |
|                               | - Zero Third-Party Drivers   |                                    |
|                               +------------------------------+                                    |
|                                              |                                                    |
+---------------------------------------------------------------------------------------------------+
                                               |
                                     GET /api/v1/stream (SSE)
                                               v
                            +-----------------------------------------------+
                            |            CONSOLA SOC EN TIEMPO REAL         |
                            |    - Eventos en vivo con Live Pulse           |
                            |    - RBAC: Admin / Analyst / Viewer           |
                            |    - Forense con Modal de Detalle Criptográfico|
                            +-----------------------------------------------+
```

---

## ⚡ Especificaciones Técnicas

| Característica | Detalle |
| :--- | :--- |
| **Runtime** | Node.js v20.x, v22.x LTS o v24.x |
| **Dependencias en Runtime** | **0 (Cero dependencias npm)** |
| **Tiempo de Arranque** | < 60 ms |
| **Consumo de Memoria** | ~28 MB RSS |
| **Motor de Almacenamiento** | SQLite nativo en modo WAL con migraciones automáticas |
| **Criptografía** | Módulo `crypto` de Node.js (`SHA-256`, `scrypt`, `timingSafeEqual`) |
| **Cobertura de Pruebas** | 172 tests unitarios e integrados passing al 100% |

---

## 🚀 Inicio Rápido

### 1. Clonar el Repositorio
```bash
git clone https://github.com/Holasoyandres/WebSentinel-CS.git
cd WebSentinel-CS
```

### 2. Configuración de Entorno
Copia la plantilla de variables de entorno y ajusta tus credenciales:
```bash
cp .env.example .env # O edita las variables requeridas
```

### 3. Ejecución del Servidor
```bash
npm start
```
*(En Windows también puedes ejecutar `iniciar_centinela.bat`)*

Abre tu navegador en:
```
http://127.0.0.1:4000
```

---

## 🧪 Ejecución de Pruebas Automatizadas

WebSentinel-CS incluye una suite exhaustiva de pruebas usando el corredor nativo `node --test` y `php`:

```bash
# Ejecutar la suite completa de 172 pruebas de Node.js
npm test

# Ejecutar las pruebas del paquete de integración de Laravel (PHP 8.2+)
cd integrations/laravel && php tests/run.php
```

### Benchmark de Detección (Corpus Test)
La suite [`test/corpus.test.js`](test/corpus.test.js) audita la efectividad contra vectores reales y asegura una tasa de falsos positivos de **0%** en textos legítimos en español con comillas, guiones y caracteres internacionales.

---

## 📚 Documentación Adicional

- 📖 **[Especificación de la API REST (docs/API.md)](docs/API.md)**: Detalle completo de endpoints, parámetros, cabeceras, códigos HTTP y ejemplos JSON.
- 🚀 **[Guía de Despliegue en Producción (docs/DEPLOY.md)](docs/DEPLOY.md)**: Instrucciones paso a paso para Linux (systemd + Nginx con SSE), Windows Server (NSSM) y PM2.
- 🐘 **[Guía de Integración Laravel (integrations/laravel/README.md)](integrations/laravel/README.md)**: Configuración para Laravel 10, 11 y 12.
- 📜 **[Historial Completo de Conversación y Auditoría (docs/HISTORIAL_COMPLETO_CHAT.md)](docs/HISTORIAL_COMPLETO_CHAT.md)**: Registro íntegro de la conversación, auditorías de seguridad, prompts, decisiones técnicas e iteraciones de desarrollo.

---

## 👥 Contribuciones y Licencia

Este proyecto está bajo la licencia **MIT**. Para más detalles, consulta el archivo [LICENSE](LICENSE).

Desarrollado y mantenido por **Holasoyandres** ([GitHub](https://github.com/Holasoyandres/WebSentinel-CS)).
