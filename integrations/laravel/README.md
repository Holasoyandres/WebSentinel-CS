# 🛡️ WebSentinel-CS :: Laravel Integration Package

Paquete de integración oficial de **WebSentinel-CS** para aplicaciones **Laravel 10, 11 y 12** con soporte para PHP 8.1, 8.2, 8.3 y 8.4.

Proporciona protección de capa 7 (WAF heurístico), trampa inteligente honeypot contra bots, auditoría en tiempo real de sesiones de usuario y telemetría asíncrona hacia el Centinela con **impacto de latencia cero** y **fail-open absoluto**.

---

## 🚀 Capacidades Principales

1. **Firewall WAF Heurístico con Normalización Multicapa**:
   - Inspección previa con decodificación recursiva de URL (hasta 3 pasadas para mitigar `%2527`).
   - Decodificación de entidades HTML y colapso de comentarios SQL `/* ... */`.
   - Inspección en parámetros de cuerpo (JSON / POST), Query Strings, Path y Headers críticos (`User-Agent`, `Referer`).
   - Mitigación confirmada contra **CWE-89 (SQLi)**, **CWE-79 (XSS moderno como `<svg/onanimationstart=alert(1)>`)**, **CWE-22 (Path Traversal/LFI)** y **CWE-78 (Command Injection)**.
   - **0% falsos positivos**: Tratamiento seguro de guiones dobles (`--`), nombres con apóstrofe (`O'Reilly`) y dominios con `.env` (`enviaexpress.com`).
   - **Filtrado estricto de privacidad**: Exclusión automática de contraseñas (`password`, `current_password`, etc.), tokens CSRF y credenciales de la inspección y de los logs.
   - **Lista blanca con soporte CIDR**: Permite rangos completos (ej. `192.168.1.0/24`).

2. **Auditoría de Sesiones y Telemetría SOC en Vivo**:
   - Listeners automáticos para `Illuminate\Auth\Events\Login`, `Failed` y `Logout`.
   - Alimenta directamente la pestaña **"Auditoría de Sesiones"** del dashboard de WebSentinel con usuarios reales.
   - Nutre el limitador de fuerza bruta persistente (`ip_reputation`).
   - Middleware opcional `WebSentinelTrackActivity` para registrar las rutas y controladores ejecutados por usuarios autenticados.

3. **Trampa Honeypot contra Bots y Crawlers**:
   - Componente Blade `<x-websentinel-honeypot />` y directiva `@websentinelHoneypot`.
   - Ocultamiento inteligente por CSS (fuera de pantalla, opacidad 0, `pointer-events: none`, `tabindex="-1"`).
   - Detección de envíos robóticos instantáneos con token criptográfico firmado (`< 1 segundo`).

4. **Telemetría Fuera de Banda (Impacto Cero en Latencia)**:
   - Despacho diferido en el hook `app()->terminating(...)` una vez que la respuesta HTTP ha sido enviada al cliente.
   - **Garantía Fail-Open**: Timeout estricto de red de 200 ms. Si el Centinela está apagado o inaccesible, la aplicación Laravel nunca falla ni experimenta lentitud.

---

## 📦 Instalación

### 1. Requerir en `composer.json`

Si estás integrando el paquete desde una ruta local dentro de tu monorepositorio:

```json
"repositories": [
    {
        "type": "path",
        "url": "../WebSentinel-CS/integrations/laravel"
    }
],
"require": {
    "websentinel/laravel-sentinel": "*"
}
```

Luego ejecuta:
```bash
composer update websentinel/laravel-sentinel
```

### 2. Publicar la configuración (opcional)

```bash
php artisan vendor:publish --tag=websentinel-config
```

---

## ⚙️ Configuración (`.env`)

Agrega estas variables en tu archivo `.env` de Laravel:

```env
# URL del daemon central WebSentinel-CS
WEBSENTINEL_DAEMON_URL=http://127.0.0.1:4000

# API Key generada en el Centinela con scope 'ingest'
WEBSENTINEL_API_KEY=ws_sec_tu_api_key_aqui

# Modo de operación: 'block' (bloquea con 403 y código SEC-...) o 'monitor' (audita sin bloquear)
WEBSENTINEL_MODE=block

# Telemetría asíncrona no bloqueante (recomendado: true)
WEBSENTINEL_ASYNC=true

# Timeout máximo de despacho en milisegundos (fail-open)
WEBSENTINEL_TIMEOUT_MS=200

# Parámetros del Honeypot
WEBSENTINEL_HONEYPOT=websentinel_verification_token
WEBSENTINEL_HONEYPOT_TIME=websentinel_ts
WEBSENTINEL_HONEYPOT_MIN_TIME=1

# Auditoría de actividad de usuarios autenticados
WEBSENTINEL_TRACK_ACTIVITIES=true
```

---

## 🛡️ Registro del Middleware Firewall

### En Laravel 11 y 12 (`bootstrap/app.php`)

```php
use WebSentinel\Http\Middleware\WebSentinelFirewall;
use WebSentinel\Http\Middleware\WebSentinelTrackActivity;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // 1. Activar el Firewall WAF en todas las peticiones entrantes
        $middleware->append(WebSentinelFirewall::class);

        // 2. (Opcional) Activar el rastreo de actividad para usuarios autenticados
        $middleware->appendToGroup('web', WebSentinelTrackActivity::class);
    })
    ->create();
```

### En Laravel 10 (`app/Http/Kernel.php`)

```php
protected $middleware = [
    // ...
    \WebSentinel\Http\Middleware\WebSentinelFirewall::class,
];

protected $middlewareGroups = [
    'web' => [
        // ...
        \WebSentinel\Http\Middleware\WebSentinelTrackActivity::class,
    ],
];
```

---

## 🤖 Uso del Componente Honeypot en Formularios Blade

Inserta el componente o directiva dentro de cualquier formulario HTML/Blade para bloquear bots automáticos:

```blade
<form method="POST" action="{{ route('login') }}">
    @csrf

    <!-- Trampa invisible e inaccesible para humanos, pero completada por crawlers -->
    <x-websentinel-honeypot />
    {{-- O alternativamente: @websentinelHoneypot --}}

    <div>
        <label>Correo Electrónico</label>
        <input type="email" name="email" required>
    </div>

    <div>
        <label>Contraseña</label>
        <input type="password" name="password" required>
    </div>

    <button type="submit">Iniciar Sesión</button>
</form>
```

---

## 🧪 Pruebas Automatizadas

El paquete incluye una suite de pruebas independiente compatible con PHP 8.1+:

```bash
cd integrations/laravel
php tests/run.php
```

Salida esperada:
```text
▶ WebSentinel :: PHP Normalizer (Normalizer.php)
  ✔ Recursive URL decoding resolves double and triple encoding
  ✔ Decodes HTML numeric and named entities
  ✔ Strips null bytes and inline SQL comments
  ✔ Truncates inputs > 16 KB for ReDoS boundary protection

▶ WebSentinel :: WAF Firewall Middleware (WebSentinelFirewall.php)
  ✔ Blocks SQL Injection (Tautology) in Body
  ✔ Blocks XSS (Event Handler) in Query Parameters
  ✔ Blocks Path Traversal in Header (User-Agent)
  ✔ Allows benign Spanish texts with hyphens and apostrophes (Zero False Positives)
  ✔ CIDR Whitelist allows requests from trusted subnets (192.168.1.0/24)
  ✔ Excludes sensitive fields (passwords, tokens) from inspection and logs

▶ WebSentinel :: Honeypot Component & Bot Defense (Honeypot.php)
  ✔ Traps automated bot filling the hidden honeypot field
  ✔ Traps speed bot submitting in less than 1 second
  ✔ Allows human submission after minimum elapsed time threshold
  ✔ Renders inaccessible, off-screen CSS honeypot markup

▶ WebSentinel :: SentinelClient Telemetry & Fail-Open (SentinelClient.php)
  ✔ Dispatches structured telemetry to POST /api/v1/events on live daemon
  ✔ Fail-open guarantee: when daemon is offline, response finishes in < 250ms with no crash

Total: 16 | Passed: 16 | Failed: 0
```
