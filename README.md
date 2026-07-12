# Proxy SOCKS5 — Protocolos de Comunicación

## 1. Ubicación de los materiales

- **`src/server/`** — Servidor proxy SOCKS5 (`socks5/`) y protocolo de management (`management/`).
- **`src/client/`** — Cliente CLI de management.
- **`src/shared/`** — Infraestructura compartida (selector, buffers, STM).
- **`scripts/`** — Pruebas de estrés y gráficos (`run_stress.sh`, resultados en `scripts/results/`).
- **`informe.tex`** — Fuente LaTeX del informe (PDF generado aparte).
- **`AGENTS.md`** — Convenciones del proyecto.

## 2. Compilación

```bash
make clean && make all
```

## 3. Artefactos

| Artefacto | Ruta |
|-----------|------|
| Servidor SOCKS5 | `bin/server` |
| Cliente de management | `bin/client` |

Objetos intermedios en `obj/`.

## 4. Ejecución

### Servidor

```bash
./bin/server
```

Por defecto:

- SOCKS5 en puerto **1080** (dual-stack).
- Management en **127.0.0.1:8080**.
- Secreto de management: **`changeme`** (cambiar con `-A`).

Opciones relevantes: `-l`, `-p`, `-L`, `-P`, `-A <secreto>`, `-u usuario:contraseña`.

Los accesos exitosos se escriben a **stdout**. Para guardarlos:

```bash
./bin/server -A mi_secreto -u admin:admin123 > access.log
```

### Cliente de management

```bash
./bin/client [opciones] <comando>
```

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-L <ip>` | IP del management | `127.0.0.1` |
| `-P <puerto>` | Puerto de management | `8080` |
| `-A <secreto>` | Secreto del protocolo | `changeme` |

| Comando | Descripción |
|---------|-------------|
| `get-metrics` | Métricas (activas, históricas, bytes) |
| `add-user <user> <pass>` | Alta de usuario SOCKS |
| `del-user <user>` | Baja de usuario |
| `set-secret <nuevo>` | Cambia el secreto (usa `-A` como actual) |

Ejemplos:

```bash
./bin/client -A mi_secreto get-metrics
./bin/client -A mi_secreto add-user alice secret123
./bin/client -A mi_secreto -L 192.168.1.10 -P 9090 del-user alice
```

### Estrés

```bash
bash scripts/run_stress.sh
```

Genera CSV y PNG en `scripts/results/`.
