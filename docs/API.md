# WebSentinel-CS :: API Reference Specification

Documentación técnica detallada de la interfaz REST y endpoints de streaming de **WebSentinel-CS (v1.3.0)**.

---

## 🔐 Autenticación y Autorización

WebSentinel-CS soporta dos mecanismos de autenticación:

1. **API Keys (M2M / Clientes como Laravel)**:
   - Cabecera: `X-Sentinel-Key: <api_key>` o `Authorization: Bearer <api_key>`.
   - Alcances (*scopes*):
     - `ingest`: Ingesta de eventos (`POST /api/v1/events`, `POST /api/analyze-request`, `POST /api/record-login`, `POST /api/sessions/*`).
     - `read`: Consulta de telemetría y métricas (`GET /api/stats`, `GET /api/events`, `GET /api/v1/ip/:ip/status`, `GET /api/v1/stream`).
     - `admin`: Acceso irrestricto a endpoints operacionales y administrativos.
2. **Sesiones Web (Dashboard SOC)**:
   - Cookie de sesión `sentinel_session` (atributos: `HttpOnly`, `SameSite=Strict`, `Secure` en producción).
   - Protección CSRF: En métodos mutantes (`POST`, `PUT`, `DELETE`), se exige la cabecera `X-CSRF-Token: <token>` coincidente con el token de sesión.
   - Roles RBAC:
     - `viewer`: Vista de solo lectura del SOC y métricas.
     - `analyst`: Lectura, ejecución de escaneos heurísticos y exportación de reportes CSV.
     - `admin`: Control total, consola forense SQL y gestión de seguridad (API Keys y desbloqueo de IPs).

---

## 📡 Resumen de Endpoints

| Método | Endpoint | Scopes / Roles Requeridos | Descripción |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | Público | Sondeo de salud del daemon y verificación de SQLite. |
| `GET` | `/readyz` | Público | Sondeo de preparación de la API para tráfico. |
| `POST` | `/api/auth/login` | Público (Con Rate Limiting) | Autenticación de usuarios del SOC con protección de timing. |
| `POST` | `/api/auth/logout` | Sesión Activa | Cierre de sesión y revocación inmediata de token. |
| `GET` | `/api/auth/me` | Sesión Activa | Identidad y rol del usuario autenticado actual. |
| `GET` | `/api/v1/stream` | `read`, `ingest`, o Sesión | Streaming de eventos en tiempo real vía Server-Sent Events (SSE). |
| `GET` | `/api/stats` | `read`, `admin`, o Sesión | Contadores agregados, tasa de bloqueos y métricas de seguridad. |
| `GET` | `/api/events` | `read`, `admin`, o Sesión | Lista paginada y filtrada de incidentes de seguridad. |
| `POST` | `/api/v1/events` | `ingest`, `admin` | Ingesta estructurada de incidentes con encadenamiento SHA-256. |
| `GET` | `/api/export-csv` | `analyst`, `admin` (No `viewer` ni `ingest`) | Exportación de incidentes a CSV con neutralización de inyecciones. |
| `POST` | `/api/scan` | `analyst`, `admin` | Auditoría remota de cabeceras OWASP y postura sobre una URL. |
| `POST` | `/api/analyze-request` | `ingest`, `admin`, o Sesión | Inspección heurística WAF multivector con decodificación normalizada. |
| `POST` | `/api/record-login` | `ingest`, `admin`, o Sesión | Registro de intentos de autenticación y cálculo de ventana deslizante. |
| `GET` | `/api/v1/ip/:ip/status` | `read`, `admin`, o Sesión | Consulta de reputación e histórico de una dirección IP. |
| `GET` | `/api/v1/integrity/verify`| `admin` (Solo rol admin) | Auditoría criptográfica completa de la cadena de hashes SHA-256. |
| `POST` | `/api/sql/query` | `admin` (Solo rol admin) | Consola forense SQL aislada en Worker Thread (solo `SELECT`). |
| `GET` | `/api/sql/summary` | `analyst`, `admin` | Estadísticas analíticas de eventos agrupados por categoría. |
| `GET` | `/api/v1/admin/api-keys` | `admin` (Solo rol admin) | Lista todas las API keys activas y revocadas. |
| `POST` | `/api/v1/admin/api-keys` | `admin` (Solo rol admin) | Genera una nueva API key con scopes específicos. |
| `DELETE` | `/api/v1/admin/api-keys/:id` | `admin` (Solo rol admin) | Revoca y elimina permanentemente una API key. |
| `GET` | `/api/v1/admin/blocked-ips` | `admin` (Solo rol admin) | Consulta IPs bloqueadas con tiempo restante de enfriamiento. |
| `POST` | `/api/v1/admin/unblock-ip` | `admin` (Solo rol admin) | Desbloqueo manual auditado de una dirección IP. |

---

## 🛠️ Especificación Detallada por Endpoint

### 1. Ingesta Estructurada de Incidentes
**`POST /api/v1/events`**

Permite a agentes perimetrales (ej. paquete Laravel `SentinelClient`) registrar incidentes de seguridad con validación estricta de esquema y cálculo de hash criptográfico inmutable.

* **Autenticación**: `X-Sentinel-Key` con scope `ingest`.
* **Cuerpo de la Petición (JSON)**:
```json
{
  "source_ip": "203.0.113.42",
  "method": "POST",
  "endpoint": "/api/v1/pagos",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "category": "SQLI",
  "rule_id": "SIG-SQLI-001",
  "severity": "CRITICAL",
  "score": 8,
  "action": "BLOCKED",
  "details": "Tautología detectada: ' OR 1=1 --",
  "payload": "username=admin' OR 1=1 --&token=abc"
}
```

* **Respuesta Exitosa (`201 Created`)**:
```json
{
  "status": "INGESTED",
  "id": "SEC-B7A2F081",
  "chain_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp": "2026-10-29T15:30:00.000Z"
}
```

* **Errores**:
  - `400 Bad Request`: Faltan campos obligatorios (`source_ip`, `category`, `rule_id`, `severity`, `action`) o tipos inválidos.
  - `401 Unauthorized`: API key ausente o inválida.
  - `403 Forbidden`: API key sin scope `ingest`.

---

### 2. Streaming en Tiempo Real (Server-Sent Events)
**`GET /api/v1/stream`**

Emite un flujo continuo unidireccional de eventos en tiempo real para alimentar tableros SOC sin latencia y sin sobrecarga de sondeo (polling).

* **Cabeceras de Respuesta**:
```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache, no-transform
Connection: keep-alive
X-Accel-Buffering: no
```

* **Estructura del Flujo**:
  - Mensaje de bienvenida:
    ```
    event: connected
    data: {"status":"STREAM_READY","timestamp":"2026-10-29T15:30:00.000Z"}
    ```
  - Pulso de vida (*Heartbeat* cada 15 segundos para evitar desconexiones por cortafuegos/proxies):
    ```
    : heartbeat
    ```
  - Emisión de incidente en vivo:
    ```
    event: incident
    data: {"id":"SEC-B7A2F081","timestamp":"2026-10-29T15:30:00.000Z","source_ip":"203.0.113.42","category":"SQLI","rule_id":"SIG-SQLI-001","severity":"CRITICAL","score":8,"action":"BLOCKED","endpoint":"/api/v1/pagos","details":"Tautología detectada"}
    ```

---

### 3. Exportación Forense Sanitizada a CSV
**`GET /api/export-csv`**

Genera y descarga un reporte CSV con protección activa contra **CSV / Formula Injection** (CWE-1236).

* **Parámetros de Consulta (Opcionales)**:
  - `from`: Fecha inicio en formato ISO o YYYY-MM-DD (ej: `2026-10-01`).
  - `to`: Fecha fin en formato ISO o YYYY-MM-DD (ej: `2026-10-29`).
  - `search`: Texto libre para filtrar por IP, regla, endpoint o descripción.
* **Cabeceras de Respuesta**:
```http
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="websentinel-incidents-20261029.csv"
```
* **Mecanismo de Blindaje Anti-Formula Injection**:
  Toda celda cuyo primer caracter sea `=`, `+`, `-`, `@`, `\t` (tab) o `\r` (retorno de carro) es automáticamente prefijada con una comilla simple `'` para desarmar la ejecución de macros o fórmulas DDE al abrirse en Microsoft Excel, Google Sheets o LibreOffice Calc.

---

### 4. Inspección Heurística WAF
**`POST /api/analyze-request`**

Inspecciona payloads arbitrarios contra el motor de firmas centralizado (`rules/signatures.json`) y el pipeline de normalización recursivo.

* **Cuerpo de la Petición**:
```json
{
  "method": "POST",
  "url": "/login",
  "ip": "198.51.100.22",
  "payload": "%2527%20OR%201=1",
  "honeypot_field": ""
}
```

* **Respuesta Exitosa (`200 OK`)**:
```json
{
  "action": "BLOCKED",
  "score": 5,
  "confidence": "HIGH",
  "matches": [
    {
      "id": "SIG-SQLI-001",
      "name": "SQL Injection - Classic Tautology (OR 1=1)",
      "category": "SQLI",
      "severity": "CRITICAL",
      "cwe": "CWE-89",
      "score": 5
    }
  ],
  "normalized": "' OR 1=1",
  "timestamp": "2026-10-29T15:30:05.120Z"
}
```

---

### 5. Auditoría de Cadena Criptográfica
**`GET /api/v1/integrity/verify`**

Verifica la inmutabilidad y ordenamiento de toda la secuencia histórica de incidentes almacenada en SQLite.

* **Requisito**: Rol `admin`.
* **Respuesta Exitosa (`200 OK`)**:
```json
{
  "status": "VALID",
  "total_records": 1420,
  "verified_at": "2026-10-29T15:32:00.000Z",
  "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "latest_hash": "a4f89d34e90812bcae67812903ffba42198ecab421098421093812039840291a"
}
```

---

### 6. Gestión Administrativa de Seguridad

#### A. Listar API Keys
**`GET /api/v1/admin/api-keys`**
* **Requisito**: Rol `admin`.
* **Respuesta**:
```json
{
  "api_keys": [
    {
      "id": "key_e9a1b2c3",
      "name": "Laravel Production Cluster",
      "key_prefix": "sentinel_prod_...",
      "scopes": "ingest,read",
      "created_at": "2026-10-28T12:00:00.000Z",
      "is_active": 1
    }
  ]
}
```

#### B. Generar API Key
**`POST /api/v1/admin/api-keys`**
* **Requisito**: Rol `admin` + Cabecera `X-CSRF-Token`.
* **Cuerpo**:
```json
{
  "name": "Microservicio Facturacion",
  "scopes": ["ingest"]
}
```
* **Respuesta (`201 Created`)**:
```json
{
  "status": "CREATED",
  "apiKey": "sentinel_live_98a7f1e6b3c2d4a5..."
}
```

#### C. Revocar API Key
**`DELETE /api/v1/admin/api-keys/:id`**
* **Requisito**: Rol `admin` + Cabecera `X-CSRF-Token`.
* **Respuesta**: `{"status": "DELETED", "id": "key_e9a1b2c3"}`

#### D. Desbloqueo Manual de IP
**`POST /api/v1/admin/unblock-ip`**
* **Requisito**: Rol `admin` + Cabecera `X-CSRF-Token`.
* **Cuerpo**: `{"ip": "203.0.113.42"}`
* **Respuesta**: `{"status": "UNBLOCKED", "ip": "203.0.113.42"}`
