#ifndef ECHO_H_kJ3xQ9pLmN7vWtZ2sRbY8cHf
#define ECHO_H_kJ3xQ9pLmN7vWtZ2sRbY8cHf

#include "selector.h"

/**
 * Acepta una nueva conexión entrante sobre el socket pasivo `key->fd`,
 * la pone en modo no bloqueante y la registra en el selector para
 * reenviarle (echo) todo lo que envíe.
 *
 * Se usa como `handle_read` del fd_handler del socket pasivo.
 */
void
echo_passive_accept(struct selector_key *key);

#endif
