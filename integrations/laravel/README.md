# 🛡️ WebSentinel-CS :: Laravel Integration Package

Middleware de ciberseguridad, WAF heurístico y telemetría fuera de banda para aplicaciones **Laravel 10 / 11**.

Protege tus rutas y APIs contra:
- **CWE-89 (Inyección SQL)** en parámetros GET, POST y JSON.
- **CWE-79 (Cross-Site Scripting - XSS)** en entradas de texto.
- **CWE-22 (Path Traversal / LFI)** en subida o manipulación de archivos.
- **CWE-799 (Ataques de Fuerza Bruta)** en formularios de login.
- **Trampa Honeypot contra Bots y Crawlers automatizados.**

---

## 📦 Instalación

### 1. Incluir el paquete en tu proyecto Laravel

Si estás trabajando en local o agregándolo como repositorio de ruta en tu `composer.json`:

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

### 2. Publicar la configuración (Opcional)

```bash
php artisan vendor:publish --tag=websentinel-config
```

Esto creará `config/websentinel.php` en tu proyecto.

---

## ⚡ Activación del Firewall Middleware

### En Laravel 11 (`bootstrap/app.php`):

```php
use WebSentinel\Http\Middleware\WebSentinelFirewall;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // Aplica el firewall a todas las peticiones web y API
        $middleware->append(WebSentinelFirewall::class);
    })
    ->create();
```

### En Laravel 10 (`app/Http/Kernel.php`):

```php
protected $middleware = [
    // ...
    \WebSentinel\Http\Middleware\WebSentinelFirewall::class,
];
```

---

## ⚙️ Variables de Entorno (`.env`)

```env
# URL del daemon central de WebSentinel-CS (por defecto http://127.0.0.1:4000)
WEBSENTINEL_DAEMON_URL=http://127.0.0.1:4000

# Modo de operación: 'block' (bloquea con 403) o 'monitor' (solo registra)
WEBSENTINEL_MODE=block

# Nombre del campo trampa invisible para bots
WEBSENTINEL_HONEYPOT=websentinel_verification_token
```

---

## 🤖 Uso de Honeypot en Blade Forms

Agrega el campo trampa en tus formularios para neutralizar bots:

```html
<form method="POST" action="/login">
    @csrf
    
    <!-- Campo Honeypot invisible: ningún usuario lo ve, pero los bots lo llenan -->
    <input type="text" name="websentinel_verification_token" style="display:none;" tabindex="-1" autocomplete="off">
    
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <button type="submit">Iniciar Sesión</button>
</form>
```

Si un bot automatizado llena este campo, el middleware lo detecta y lo bloquea antes de que toque tu base de datos.
