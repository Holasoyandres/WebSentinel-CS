# WebSentinel-CS :: Production Deployment & Operations Guide

Guía exhaustiva para el despliegue, endurecimiento y operación en producción de **WebSentinel-CS** en entornos Linux y Windows Server.

---

## 📋 Requisitos Previos

- **Runtime**: Node.js v20.x, v22.x LTS o v24.x (sin módulos npm externos en runtime).
- **Base de Datos**: Motor SQLite nativo incluido en Node.js / sistema.
- **Memoria RAM mínima**: 128 MB (consumo estándar ~30 MB).
- **Disco**: 500 MB (depende del volumen de eventos y la política de retención).
- **Permisos de Archivo**: Acceso exclusivo de lectura/escritura al archivo `data/sentinel.sqlite`.

---

## ⚙️ Variables de Entorno (`.env`)

Crea un archivo `.env` en la raíz del proyecto (restringido a permisos `600`):

```bash
# Servidor HTTP y Red
PORT=4000
HOST=127.0.0.1
NODE_ENV=production
TRUST_PROXIES=true

# Almacenamiento y Base de Datos
DB_PATH=/var/lib/websentinel/sentinel.sqlite

# Retención y Mantenimiento de Incidentes
RETENTION_DAYS=90
PURGE_INTERVAL_HOURS=24
BACKUP_KEEP=14

# Secretos y Administración Inicial
ADMIN_USER=admin
ADMIN_PASSWORD=GenerarPasswordRobustoDe32Caracteres!
SESSION_SECRET=GenerarClaveAleatoriaHexadecimal64Bytes
```

---

## 🐧 Opción 1: Despliegue en Linux (Ubuntu/Debian) con Systemd & Nginx

### 1. Creación del Usuario de Servicio y Directorios
```bash
# Crear usuario de sistema sin shell interactiva
sudo useradd -r -s /bin/false -d /opt/websentinel websentinel

# Clonar o copiar el proyecto
sudo mkdir -p /opt/websentinel /var/lib/websentinel /var/log/websentinel
sudo cp -r . /opt/websentinel/

# Asignar permisos seguros
sudo chown -R websentinel:websentinel /opt/websentinel /var/lib/websentinel /var/log/websentinel
sudo chmod 700 /var/lib/websentinel
sudo chmod 600 /opt/websentinel/.env
```

### 2. Configuración del Servicio Systemd (`/etc/systemd/system/websentinel.service`)
```ini
[Unit]
Description=WebSentinel-CS Enterprise Security Sentinel Daemon
After=network.target
Documentation=https://github.com/Holasoyandres/WebSentinel-CS

[Service]
Type=simple
User=websentinel
Group=websentinel
WorkingDirectory=/opt/websentinel
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5s
KillMode=mixed
TimeoutStopSec=15s

# Endurecimiento de Seguridad de Linux (Sandboxing)
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/websentinel /var/log/websentinel

EnvironmentFile=/opt/websentinel/.env

[Install]
WantedBy=multi-user.target
```

Habilitar e iniciar el servicio:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now websentinel
sudo systemctl status websentinel
```

### 3. Configuración de Nginx Reverse Proxy con Soporte SSE

La configuración de Nginx debe deshabilitar el almacenamiento en búfer para la ruta del flujo Server-Sent Events (`/api/v1/stream`), de lo contrario los eventos se retrasarían:

```nginx
# /etc/nginx/sites-available/websentinel.conf
upstream websentinel_backend {
    server 127.0.0.1:4000;
    keepalive 32;
}

server {
    listen 80;
    server_name soc.tuorganizacion.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.tuorganizacion.com;

    ssl_certificate /etc/letsencrypt/live/soc.tuorganizacion.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.tuorganizacion.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Cabeceras globales de seguridad
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Configuración de Server-Sent Events (SSE) en tiempo real
    location /api/v1/stream {
        proxy_pass http://websentinel_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Directivas críticas para evitar que el proxy corte o acumule el stream
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        chunked_transfer_encoding on;
    }

    # Resto de la API y Consola Web
    location / {
        proxy_pass http://websentinel_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 10M;
    }
}
```

Activar y recargar Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/websentinel.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## 🪟 Opción 2: Despliegue en Windows Server con NSSM

En servidores Windows, el centinela puede correr como un servicio de fondo continuo mediante **NSSM (Non-Sucking Service Manager)**:

1. **Descargar NSSM**:
   Descarga `nssm.exe` desde [nssm.cc](https://nssm.cc/) y colócalo en `C:\Tools\nssm\`.

2. **Instalar el Servicio**:
   Abre una consola de PowerShell o CMD como **Administrador**:
   ```powershell
   C:\Tools\nssm\nssm.exe install WebSentinel-CS "C:\Program Files\nodejs\node.exe" "server.js"
   C:\Tools\nssm\nssm.exe set WebSentinel-CS AppDirectory "C:\WebSentinel-CS"
   C:\Tools\nssm\nssm.exe set WebSentinel-CS AppStdout "C:\WebSentinel-CS\data\logs\service.log"
   C:\Tools\nssm\nssm.exe set WebSentinel-CS AppStderr "C:\WebSentinel-CS\data\logs\service-error.log"
   C:\Tools\nssm\nssm.exe set WebSentinel-CS AppRotateFiles 1
   C:\Tools\nssm\nssm.exe set WebSentinel-CS AppRotateOnline 1
   C:\Tools\nssm\nssm.exe set WebSentinel-CS AppRotateSeconds 86400
   ```

3. **Iniciar el Servicio**:
   ```powershell
   Start-Service WebSentinel-CS
   Get-Service WebSentinel-CS
   ```

---

## 🚀 Opción 3: Despliegue con PM2 (Process Manager)

Para clústeres basados en PM2:

1. Ejecutar el servicio con el manifiesto incluido:
   ```bash
   pm2 start deploy/ecosystem.config.js --env production
   ```
2. Guardar la lista de procesos y activar el inicio automático con el sistema:
   ```bash
   pm2 save
   pm2 startup
   ```

---

## 🔒 Rutinas de Respaldo y Mantenimiento

### Respaldo en Caliente con SQLite Online Backup
```bash
# Ejecutar respaldo consistente en vivo
npm run backup
```
Crea una copia binaria consistente con `VACUUM INTO` sin bloquear la concurrencia de lecturas y escrituras.

### Purga Automática en Cron / Programador de Tareas
Para entornos Linux, añadir al crontab del usuario `websentinel`:
```cron
0 3 * * * cd /opt/websentinel && /usr/bin/npm run purge >> /var/log/websentinel/purge.log 2>&1
0 4 * * * cd /opt/websentinel && /usr/bin/npm run backup >> /var/log/websentinel/backup.log 2>&1
```

---

## 🩺 Verificación Post-Despliegue

Ejecuta las comprobaciones de salud inmediatas:

```bash
# 1. Comprobar salud del daemon
curl -s http://127.0.0.1:4000/healthz

# 2. Comprobar disponibilidad de endpoints
curl -s http://127.0.0.1:4000/readyz

# 3. Comprobar verificación de cadena criptográfica (requiere sesión admin)
curl -s -H "Cookie: sentinel_session=..." http://127.0.0.1:4000/api/v1/integrity/verify
```
