# AGENTS.md — Guía para agentes de IA

Proyecto: servidor proxy SOCKS5 (RFC 1928 + RFC 1929) con cliente de monitoreo/configuración.
Materia: Protocolos de Comunicación, ITBA 2026/1.
Lenguaje: C11 (ISO/IEC 9899:2011), POSIX.

---

## Estructura del repositorio

```
src/
  shared/     Código reutilizado por server y client
  server/     Proceso servidor SOCKS5
  client/     Cliente de monitoreo/configuración
obj/          Objetos compilados (generado por make, ignorar)
bin/          Binarios finales: bin/server y bin/client (generado por make)
```

El Makefile recolecta `src/server/*.c`, `src/client/*.c` y `src/shared/*.c` con wildcard.
Cualquier `.c` nuevo en esas carpetas se compila automáticamente; no modificar el Makefile
salvo que cambie la estructura de carpetas o los flags.

---

## Módulos en src/shared

| Archivo | Responsabilidad |
|---|---|
| `selector.{c,h}` | Multiplexor de I/O no bloqueante (wrappea select/poll/epoll). Núcleo del event loop. |
| `stm.{c,h}` | Motor de máquina de estados. Los estados se definen con `struct state_definition` (callbacks on_arrival, on_departure, on_read_ready, on_write_ready, on_block_ready). |
| `buffer.{c,h}` | Buffer circular para lecturas/escrituras parciales. |
| `parser.{c,h}` | Motor genérico de parsers/lexers orientado a eventos. |
| `parser_utils.{c,h}` | Factories de parsers comunes (números, strings, etc.). |
| `netutils.{c,h}` | Utilidades de red (set non-blocking, etc.). |

Los archivos `*_test.c` son tests unitarios de cada módulo. No forman parte de los binarios
`server` ni `client`; si se agregan, el Makefile los incluirá en el objeto compartido y
romperá el linkeo (múltiples `main`). Mantenerlos fuera de src/shared o agregar un target
`test` separado en el Makefile que los compile aparte.

---

## Módulos en src/server (planeados / en construcción)

| Archivo | Responsabilidad |
|---|---|
| `main.c` | Punto de entrada: parsea args, crea socket pasivo, inicia selector, event loop principal, graceful shutdown. |
| `args.{c,h}` | Parsing de argumentos de línea de comandos (`parse_args`). Llena `struct socks5args`. |
| `socks5nio.{c,h}` | Manejo non-blocking de conexiones SOCKS5: acepta clientes, delega a la STM. |
| `socks5.h` | Definición de `struct socks5` (estado por conexión), pool de objetos. |
| `hello.{c,h}` | Parser y marshaller del handshake SOCKS5 (método de autenticación). |
| `request.{c,h}` | Parser y marshaller del mensaje REQUEST de SOCKS5 (CONNECT/BIND/UDP). |
| `auth_userpass.{c,h}` | Autenticación usuario/contraseña RFC 1929. |
| `dns.{c,h}` | Resolución de FQDN vía getaddrinfo en thread separado, notifica al selector con `selector_notify_block`. |
| `metrics.{c,h}` | Contadores de conexiones históricas, concurrentes, bytes transferidos. |
| `logger.{c,h}` | Registro de accesos (usuario, destino, timestamp). |
| `mgmt.{c,h}` | Socket pasivo del protocolo de monitoreo en puerto separado. |

---

## Módulos en src/client (planeados / en construcción)

El cliente de monitoreo/configuración puede usar I/O bloqueante.

| Archivo | Responsabilidad |
|---|---|
| `main.c` | Punto de entrada del cliente. Parsea args, conecta al puerto de management. |
| `args.{c,h}` | Parsing de argumentos del cliente (puede compartir estructura con server o ser independiente). |

---

## Restricciones críticas — leer antes de escribir cualquier código

### 1. Sin blocking en el thread principal

El servidor corre en **un único thread**. Ningún handler del selector puede bloquearse.
Esto incluye: `read`, `write`, `connect`, `accept`, `getaddrinfo`, `sleep`, mutex, o cualquier
syscall que pueda bloquear indefinidamente.

Toda lectura/escritura de red se hace con sockets en modo `O_NONBLOCK`. Las lecturas y
escrituras pueden ser parciales: **siempre** usar `buffer` para acumular y manejar eso.

### 2. getaddrinfo va en un thread aparte

El único uso permitido de threads es para resolución DNS con `getaddrinfo(3)`.
Ese thread **solo** resuelve el nombre y llama `selector_notify_block` para despertar
al selector. No hace ninguna otra I/O.

Alternativa: `getaddrinfo_a(3)` que evita el thread completamente.

### 3. Lecturas y escrituras parciales

`recv`/`send` pueden retornar menos bytes de los pedidos. Siempre usar `buffer_write_ptr` /
`buffer_write_adv` y `buffer_read_ptr` / `buffer_read_adv` del módulo `buffer`. Nunca asumir
que un `recv` completa un mensaje entero.

### 4. Máquina de estados por conexión

Cada conexión tiene su propia `struct socks5` con un `struct state_machine` embebido.
Los estados siguen el patrón de `stm.h`: definir `enum` con los estados, luego
`struct state_definition[]` con los callbacks, inicializar con `stm_init`.

El handler top-level del selector (`socksv5_read`, `socksv5_write`, `socksv5_block`)
delega a `stm_handler_*` y solo chequea si el nuevo estado es `DONE` o `ERROR`.

### 5. Pool de objetos

`struct socks5` se gestiona con un pool para evitar `malloc`/`free` frecuentes bajo carga.
El patrón está en `socks5nio.c`: `pool`, `pool_size`, `max_pool`. Respetar ese patrón
al agregar estructuras similares de alta frecuencia.

---

## Convenciones de código

- **Estándar**: C11. Compilar con `-Wall -pedantic -g` (definido en `Makefile.inc`).
- **Include guards**: formato `#ifndef NOMBRE_H_<hash_largo>` como en los headers existentes.
- **Nombres**: `snake_case` para todo. Tipos opacos con `typedef struct foo * foo_t` o
  como en selector (`typedef struct fdselector * fd_selector`).
- **Sin comentarios obvios**: solo comentar el *por qué* si no es evidente. No describir
  lo que hace el código, los nombres ya lo hacen.
- **`goto finally`**: patrón aceptado y usado en `main.c` para el cleanup de recursos.
- **Headers propios antes que del sistema**: incluir primero `<sys/*.h>`, luego `"modulo.h"`.

---

## Build

```bash
make          # compila server y client
make server   # solo servidor
make client   # solo cliente
make clean    # elimina bin/ y obj/
```

Compilador: `gcc`. Flags en `Makefile.inc`. No modificar `Makefile.inc` sin consenso del grupo.

---

## Argumentos de línea de comandos

Seguir IEEE Std 1003.1-2008 (POSIX Utility Conventions). El parsing está en `args.c`
usando `getopt_long`. Las opciones actuales del servidor:

| Flag | Descripción | Default |
|---|---|---|
| `-l <addr>` | Dirección SOCKS5 | `0.0.0.0` |
| `-p <port>` | Puerto SOCKS5 | `1080` |
| `-L <addr>` | Dirección management | `127.0.0.1` |
| `-P <port>` | Puerto management | `8080` |
| `-u <user>:<pass>` | Usuario (hasta 10) | — |
| `-N` | Deshabilitar disectores | habilitados |
| `-v` | Versión | — |
| `-h` | Ayuda | — |

---

## Lo que NO hacer

- No agregar `sleep`, `usleep`, ni `nanosleep` fuera de tests.
- No llamar `getaddrinfo` directamente en un handler del selector.
- No usar `fgets`, `scanf`, ni I/O de stdio sobre sockets.
- No usar `read`/`write` en sockets sin haber activado `O_NONBLOCK` antes.
- No crear threads adicionales salvo el de DNS.
- No poner lógica de negocio en `main.c`; ese archivo solo inicializa y corre el loop.
- No romper la compatibilidad de `selector.h` y `stm.h`: son la interfaz estable del proyecto.
- No compilar los `*_test.c` junto con el servidor/cliente (causan múltiples `main`).
