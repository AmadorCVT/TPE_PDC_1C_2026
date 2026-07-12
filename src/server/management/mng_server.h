#ifndef MNG_SERVER_H_
#define MNG_SERVER_H_

#include "selector.h"

/**
 * Inicializa el servidor de management no bloqueante en la dirección y puerto dados.
 * Registra el socket pasivo en el selector.
 *
 * `secret` es la credencial que debe preceder a cada comando del protocolo
 * de management (ver mng_server.c).
 *
 * @return El fd del socket pasivo creado, o -1 en caso de error.
 */
int
mng_server_init(const char *addr, unsigned port, fd_selector selector, const char *secret);

#endif
