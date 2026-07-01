# Proxy SOCKS5 — Protocolos de Comunicación

## 1. Ubicación de los materiales

El proyecto está organizado de la siguiente manera:

- **`src/server/`** — Código fuente del servidor proxy SOCKS5, incluyendo el módulo de autenticación, el protocolo SOCKS5 y el servidor de management.
- **`src/client/`** — Código fuente del cliente de management para administrar y monitorear el servidor desde la terminal.
- **`src/shared/`** — Recursos compartidos entre servidor y cliente (selector de eventos, buffers, parsers y utilidades de red).
- **Raíz del proyecto** — Informe final del trabajo práctico en formato PDF.

## 2. Procedimiento de compilación

El proyecto utiliza **GNU Make** como sistema de compilación. Para compilar todo desde cero, ejecutar desde la raíz del repositorio:

```bash
make clean && make all
```

## 3. Ubicación de los artefactos generados

Los ejecutables compilados se guardan automáticamente en el directorio **`bin/`**:

| Artefacto | Ruta |
|-----------|------|
| Servidor SOCKS5 | `bin/server` |
| Cliente de management | `bin/client` |

Los archivos objeto intermedios (`.o`) se almacenan en `obj/` durante la compilación.

## 4. Instrucciones de ejecución y opciones

### Servidor SOCKS5

Para levantar el servidor con la configuración por defecto:

```bash
./bin/server
```

Por defecto:

- El proxy SOCKS5 escucha en el puerto **1080** (todas las interfaces, `0.0.0.0`).
- El servidor de management escucha en el puerto **8080** (interfaz local, `127.0.0.1`).

El puerto del servicio de management puede cambiarse con la opción **`-P`**. Otras opciones del servidor incluyen `-l` (dirección SOCKS), `-L` (dirección de management), `-p` (puerto SOCKS) y `-u` (usuarios iniciales en formato `usuario:contraseña`).

Ejemplo con puerto de management personalizado:

```bash
./bin/server -P 9090
```

### Cliente de Management

Sintaxis general:

```bash
./bin/client [opciones] <comando>
```

**Opciones:**

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| `-L <ip>` | Dirección IP del servidor de management | `127.0.0.1` |
| `-P <puerto>` | Puerto del servidor de management | `8080` |

**Comandos disponibles:**

| Comando | Descripción |
|---------|-------------|
| `get-metrics` | Obtiene las métricas actuales del servidor |
| `add-user <user> <pass>` | Agrega un usuario autorizado para usar el proxy |
| `del-user <user>` | Elimina un usuario previamente registrado |

**Ejemplos de uso:**

Consultar métricas del servidor local:

```bash
./bin/client get-metrics
```

Agregar un usuario al proxy:

```bash
./bin/client add-user alice secret123
```

Eliminar un usuario y conectarse a un servidor de management en otro host/puerto:

```bash
./bin/client -L 192.168.1.10 -P 9090 del-user alice
```
