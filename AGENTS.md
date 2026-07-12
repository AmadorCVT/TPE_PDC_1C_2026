# AGENTS.md — Guía para agentes de IA

Proyecto: servidor proxy SOCKS5 (RFC 1928 + RFC 1929) con cliente de monitoreo/configuración.
Materia: Protocolos de Comunicación, ITBA 2026/1.
Lenguaje: C11 (ISO/IEC 9899:2011), POSIX.

---

## Estructura del repositorio

```
src/
  shared/                 Infraestructura reutilizable (selector, buffer, stm, parser)
  server/
    main.c, args.c/h      Entrada del servidor y parseo CLI
    socks5/               Proxy SOCKS5 (parsers + máquina de estados)
    management/           Protocolo de monitoreo/configuración
  client/                 Cliente CLI del protocolo de management
obj/                      Objetos compilados (generado por make)
bin/                      bin/server y bin/client (generado por make)
scripts/                  Pruebas de estrés y gráficos
informe.tex               Fuente LaTeX del informe
```

El Makefile recolecta `src/server/*.c`, `src/server/socks5/*.c`,
`src/server/management/*.c`, `src/client/*.c` y `src/shared/*.c`.
Los `*_test.c` se excluyen del build de server/client (tienen su propio `main`).

---

## Módulos en src/shared

Código base reutilizado (parte de la cátedra / infraestructura común):

| Archivo | Responsabilidad |
|---|---|
| `selector.{c,h}` | Multiplexor de I/O no bloqueante (`pselect`). |
| `stm.{c,h}` | Motor de máquina de estados. |
| `buffer.{c,h}` | Buffer circular para lecturas/escrituras parciales. |
| `parser.{c,h}` / `parser_utils.{c,h}` | Parsers genéricos orientados a eventos. |
| `netutils.{c,h}` | Utilidades de red. |

---

## Módulos propios del servidor

| Archivo | Responsabilidad |
|---|---|
| `server/main.c` | Sockets pasivos, selector, graceful shutdown (SIGTERM/SIGINT). |
| `server/args.{c,h}` | CLI: `-l/-p` SOCKS, `-L/-P` management, `-u`, `-A` secreto. |
| `server/socks5/socks5nio.{c,h}` | STM SOCKS5 + túnel COPY con write optimista. |
| `server/socks5/hello.{c,h}` | Parser HELLO (RFC 1928 §3). |
| `server/socks5/auth.{c,h}` | Auth usuario/contraseña (RFC 1929). |
| `server/socks5/request.{c,h}` | Parser REQUEST CONNECT (IPv4/IPv6/FQDN). |
| `server/management/mng_server.{c,h}` | Protocolo de management con secreto compartido. |

---

## Cliente de management

| Archivo | Responsabilidad |
|---|---|
| `client/client.c` | CLI bloqueante: envía comando, parsea `+OK`/`-ERR`, imprime salida humana. |

Opciones: `-L`, `-P`, `-A`. Comandos: `get-metrics`, `add-user`, `del-user`, `set-secret`.

---

## Restricciones críticas

### 1. Sin blocking en el thread principal

El servidor corre en **un único thread** de I/O. Ningún handler del selector puede
bloquearse (`read`/`write`/`connect`/`accept`/`getaddrinfo` bloqueantes, `sleep`, etc.).

Excepción permitida: resolución DNS con `getaddrinfo` en un pthread auxiliar que
notifica al selector con `selector_notify_block`.

### 2. Lecturas y escrituras parciales

Siempre asumir que `recv`/`send` pueden devolver menos bytes de los pedidos.
En COPY: tras un `recv` exitoso se intenta un `send` inmediato al peer
(`select → read → write`); si no entra todo, el resto queda en el buffer y se
espera `OP_WRITE`.

### 3. Protocolo de management

Cada comando lleva el secreto como primer token:

```
<secret> GET_METRICS\n
<secret> ADD_USER <user> <pass>\n
<secret> DEL_USER <user>\n
<secret> SET_SECRET <new>\n
```

Respuestas: una línea `+OK ...\r\n` o `-ERR ...\r\n`.

### 4. Logging

Los accesos se escriben a **stdout** (redirigible). No abrir archivos desde el
event loop salvo que sea inevitable.

### 5. Compilación

```bash
make clean && make all
```

Flags: `-Wall -pedantic` (sin `-g` en el build de entrega).

---

## Convenciones

- Responder en español al usuario del proyecto cuando corresponda.
- No inventar módulos “planeados”: el código actual es la fuente de verdad.
- No documentar utilidades de la cátedra como aporte propio en el informe.
- Preferir cambios mínimos y enfocados; no refactors cosméticos.
