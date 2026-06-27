#ifndef SOCKS5NIO_H_4mTqZ8sVbN2hKpRxLwYcUgEa
#define SOCKS5NIO_H_4mTqZ8sVbN2hKpRxLwYcUgEa

#include <stdbool.h>

#include "selector.h"

/**
 * socks5nio.h - manejo non-blocking de conexiones SOCKS5.
 *
 * Acepta clientes sobre el socket pasivo y delega cada conexión a una
 * máquina de estados (stm.h) que encadena los parsers de HELLO, AUTH y
 * REQUEST, resuelve el destino y copia el tráfico de forma bidireccional.
 */

/**
 * Acepta una nueva conexión SOCKS5 entrante sobre `key->fd`, la pone en modo
 * no bloqueante y la registra en el selector.
 *
 * Se usa como `handle_read` del fd_handler del socket pasivo.
 */
void
socksv5_passive_accept(struct selector_key *key);

/**
 * Libera el pool de estructuras `struct socks5` reutilizadas.
 * Llamar una vez antes de terminar el programa.
 */
void
socksv5_pool_destroy(void);

/**
 * Cantidad de conexiones SOCKS5 vivas. Usado por el graceful shutdown para
 * saber cuándo drenaron todas las conexiones existentes.
 */
unsigned
socksv5_active_connections(void);

/**
 * Registra un usuario habilitado para autenticarse con USER/PASS (RFC 1929).
 *
 * Si hay al menos un usuario registrado el servidor exige autenticación
 * usuario/contraseña; si no hay ninguno acepta el método "sin autenticación".
 *
 * @return true si se registró, false si la tabla está llena o los argumentos
 *         son inválidos.
 */
bool
socks5_add_user(const char *user, const char *pass);

#endif
