/**
 * echo.c - servidor de echo no bloqueante
 *
 * Reenvía a cada cliente exactamente los bytes que recibe. 
 *
 * No usa máquina de estados. Se hace un echo server para ver que el servidor tenga respuesta optima.
 */
#include <stdlib.h>      // malloc, free
#include <stdint.h>      // uint8_t
#include <string.h>      // memset
#include <errno.h>       // errno, EAGAIN, EWOULDBLOCK
#include <unistd.h>      // close
#include <sys/socket.h>  // accept, recv, send

#include "echo.h"
#include "buffer.h"

/** capacidad del buffer de cada conexión */
#define ECHO_BUFFER_SIZE 4096

/** estado de una conexión de echo */
struct echo {
    /** descriptor del cliente */
    int      client_fd;

    /** datos en tránsito: lo recibido todavía no devuelto */
    buffer   buffer;
    uint8_t  raw_buffer[ECHO_BUFFER_SIZE];
};

/* handlers de selección de una conexión de echo ya aceptada */
static void echo_read (struct selector_key *key);
static void echo_write(struct selector_key *key);
static void echo_close(struct selector_key *key);

static const struct fd_handler echo_handler = {
    .handle_read  = echo_read,
    .handle_write = echo_write,
    .handle_close = echo_close,
    .handle_block = NULL,
};

/**
 * Recalcula los intereses del fd según el estado del buffer:
 *   - hay lugar para recibir  -> nos interesa leer  (OP_READ)
 *   - hay datos para devolver  -> nos interesa escribir (OP_WRITE)
 *
 * Así nunca despertamos al selector sin tener trabajo real que hacer.
 */
static void
echo_update_interests(struct selector_key *key, struct echo *e) {
    fd_interest interest = OP_NOOP;
    if(buffer_can_write(&e->buffer)) {
        interest |= OP_READ;
    }
    if(buffer_can_read(&e->buffer)) {
        interest |= OP_WRITE;
    }
    selector_set_interest_key(key, interest);
}

/** crea el estado de una nueva conexión de echo */
static struct echo *
echo_new(const int client_fd) {
    struct echo *e = malloc(sizeof(*e));
    if(e == NULL) {
        return NULL;
    }
    memset(e, 0, sizeof(*e));
    e->client_fd = client_fd;
    buffer_init(&e->buffer, ECHO_BUFFER_SIZE, e->raw_buffer);
    return e;
}

void
echo_passive_accept(struct selector_key *key) {
    struct sockaddr_storage  client_addr;
    socklen_t                client_addr_len = sizeof(client_addr);
    struct echo             *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = echo_new(client);
    if(state == NULL) {
        goto fail;
    }
    if(SELECTOR_SUCCESS != selector_register(key->s, client, &echo_handler,
                                             OP_READ, state)) {
        goto fail;
    }
    return;
fail:
    if(client != -1) {
        close(client);
    }
    free(state);
}

/** hay datos para leer del cliente: los guardamos y actualizamos intereses */
static void
echo_read(struct selector_key *key) {
    struct echo *e = key->data;
    size_t       count;
    uint8_t     *ptr = buffer_write_ptr(&e->buffer, &count);
    const ssize_t n  = recv(key->fd, ptr, count, 0);

    if(n > 0) {
        buffer_write_adv(&e->buffer, n);
        echo_update_interests(key, e);
    } else if(n == 0) {
        // el cliente cerró su lado: terminamos la conexión
        selector_unregister_fd(key->s, key->fd);
    } else if(errno != EAGAIN && errno != EWOULDBLOCK) {
        selector_unregister_fd(key->s, key->fd);
    }
}

/** podemos escribir: devolvemos al cliente lo que tengamos en el buffer */
static void
echo_write(struct selector_key *key) {
    struct echo *e = key->data;
    size_t       count;
    uint8_t     *ptr = buffer_read_ptr(&e->buffer, &count);
    const ssize_t n  = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if(n >= 0) {
        buffer_read_adv(&e->buffer, n);
        echo_update_interests(key, e);
    } else if(errno != EAGAIN && errno != EWOULDBLOCK) {
        selector_unregister_fd(key->s, key->fd);
    }
}

/** el selector desregistró el fd: cerramos y liberamos el estado */
static void
echo_close(struct selector_key *key) {
    struct echo *e = key->data;
    if(key->fd != -1) {
        close(key->fd);
    }
    free(e);
}
