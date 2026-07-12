/**
 * La conexión se modela con una máquina de estados (stm.h) que encadena los
 * parsers ya existentes:
 *
 *   HELLO_READ -> HELLO_WRITE -> [AUTH_READ -> AUTH_WRITE] -> REQUEST_READ
 *      -> REQUEST_RESOLV -> REQUEST_CONNECTING -> REQUEST_WRITE -> COPY
 *      -> DONE / ERROR
 *
 * Auth y resolve son "opcionales"
 */
#include <stdio.h>
#include <stdlib.h>   
#include <string.h>   
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>   // close
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "buffer.h"
#include "stm.h"
#include "netutils.h"

#include "hello.h"
#include "auth.h"
#include "request.h"
#include "socks5nio.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** tamaño de los buffers de I/O de cada conexión */
#define BUFFER_SIZE 4096

/** cantidad máxima de usuarios que admite la tabla de autenticación */
#define SOCKS5_MAX_USERS 10

/** obtiene el struct (socks5 *) desde la llave de selección */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data )

/** máquina de estados general de una conexión SOCKS5 */
enum socks_v5state {
    /** lee y procesa el `hello' del cliente (OP_READ sobre client_fd) */
    HELLO_READ = 0,
    /** envía la respuesta del `hello' (OP_WRITE sobre client_fd) */
    HELLO_WRITE,
    /** lee y procesa la autenticación usuario/contraseña (RFC 1929) */
    AUTH_READ,
    /** envía la respuesta de autenticación */
    AUTH_WRITE,
    /** lee y procesa el `request' (CONNECT) del cliente */
    REQUEST_READ,
    /** espera la resolución del FQDN en un thread aparte */
    REQUEST_RESOLV,
    /** espera que termine el connect no bloqueante al origin (OP_WRITE) */
    REQUEST_CONNECTING,
    /** envía la respuesta del `request' al cliente */
    REQUEST_WRITE,
    /** copia bidireccional cliente <-> origin */
    COPY,

    // estados terminales
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Estructuras de cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    buffer              *rb, *wb;
    struct hello_parser  parser;
    /** método de autenticación seleccionado */
    uint8_t              method;
};

/** usado por AUTH_READ, AUTH_WRITE */
struct auth_st {
    buffer              *rb, *wb;
    struct auth_parser   parser;
    struct auth_result   result;
    /** estado a responder (RFC 1929) */
    uint8_t              status;
};

/** usado por REQUEST_READ, REQUEST_RESOLV, REQUEST_CONNECTING, REQUEST_WRITE */
struct request_st {
    buffer               *rb, *wb;
    struct request_parser parser;
    struct request_result result;
    /** código REP a responder */
    uint8_t               status;
};

/** usado por COPY: una mitad del túnel cliente<->origin */
struct copy {
    int         *fd;
    buffer      *rb;
    buffer      *wb;
    fd_interest  duplex;
    struct copy *other;
};

/*
 * Estado por conexión. Una única alocación por conexión entrante; los estados
 * que no coexisten comparten memoria vía uniones. Un contador de referencias
 * permite saber cuándo liberar (el origin_fd comparte el mismo attachment), y
 * un pool reutiliza alocaciones previas.
 */
struct socks5 {
    /** dirección del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /** resolución de nombres del origin */
    struct addrinfo              *origin_resolution;
    struct addrinfo              *origin_resolution_current;
    /** dirección del origin a la que conectamos */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    int                           origin_fd;

    /** destino solicitado (copiado fuera de la unión para sobrevivir a COPY) */
    char                          dest_fqdn[0x100];
    uint16_t                      dest_port;   // host byte order

    /** usuario autenticado, o "anonymous" si no hubo autenticación */
    char                          client_username[256];

    /** máquina de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct auth_st            auth;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct copy               copy;
    } orig;

    /** buffers de I/O */
    uint8_t                       raw_buff_a[BUFFER_SIZE];
    uint8_t                       raw_buff_b[BUFFER_SIZE];
    buffer                        read_buffer, write_buffer;

    /** cantidad de referencias a este objeto (client_fd + origin_fd) */
    unsigned                      references;
    /** siguiente en el pool de objetos */
    struct socks5                *next;
};

////////////////////////////////////////////////////////////////////
// Declaraciones forward

static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static void socksv5_done   (struct selector_key *key);
static void log_access     (struct socks5 *s);

static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

static void     hello_read_init    (const unsigned state, struct selector_key *key);
static unsigned hello_read         (struct selector_key *key);
static unsigned hello_write        (struct selector_key *key);

static void     auth_read_init     (const unsigned state, struct selector_key *key);
static unsigned auth_read          (struct selector_key *key);
static unsigned auth_write         (struct selector_key *key);

static void     request_read_init  (const unsigned state, struct selector_key *key);
static unsigned request_read       (struct selector_key *key);
static unsigned request_resolv_done(struct selector_key *key);
static unsigned request_connecting (struct selector_key *key);
static unsigned request_write      (struct selector_key *key);

static void     copy_init          (const unsigned state, struct selector_key *key);
static unsigned copy_read          (struct selector_key *key);
static unsigned copy_write         (struct selector_key *key);

/** definición de los estados (debe estar ordenada por .state) */
static const struct state_definition client_statbl[] = {
    {
        .state         = HELLO_READ,
        .on_arrival    = hello_read_init,
        .on_read_ready = hello_read,
    }, {
        .state          = HELLO_WRITE,
        .on_write_ready = hello_write,
    }, {
        .state         = AUTH_READ,
        .on_arrival    = auth_read_init,
        .on_read_ready = auth_read,
    }, {
        .state          = AUTH_WRITE,
        .on_write_ready = auth_write,
    }, {
        .state         = REQUEST_READ,
        .on_arrival    = request_read_init,
        .on_read_ready = request_read,
    }, {
        .state          = REQUEST_RESOLV,
        .on_block_ready = request_resolv_done,
    }, {
        .state          = REQUEST_CONNECTING,
        .on_write_ready = request_connecting,
    }, {
        .state          = REQUEST_WRITE,
        .on_write_ready = request_write,
    }, {
        .state         = COPY,
        .on_arrival    = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready= copy_write,
    }, {
        .state = DONE,
    }, {
        .state = ERROR,
    },
};

////////////////////////////////////////////////////////////////////
// Tabla de usuarios (autenticación usuario/contraseña)

struct socks5_user {
    char user[256];
    char pass[256];
    bool in_use;
};

static struct socks5_user users[SOCKS5_MAX_USERS];
static unsigned           users_count = 0;

bool
socks5_add_user(const char *user, const char *pass) {
    if (user == NULL || pass == NULL || users_count >= SOCKS5_MAX_USERS) {
        return false;
    }
    if (strlen(user) >= sizeof(users[0].user) ||
        strlen(pass) >= sizeof(users[0].pass)) {
        return false;
    }
    struct socks5_user *u = &users[users_count++];
    strcpy(u->user, user);
    strcpy(u->pass, pass);
    u->in_use = true;
    return true;
}

int
socks5_remove_user(const char *user) {
    if (user == NULL) {
        return -1;
    }
    for (unsigned i = 0; i < SOCKS5_MAX_USERS; i++) {
        if (users[i].in_use && strcmp(users[i].user, user) == 0) {
            users[i].in_use = false;
            // Shift subsequent users left to compact the array and keep it contiguous
            for (unsigned j = i; j < SOCKS5_MAX_USERS - 1; j++) {
                users[j] = users[j + 1];
            }
            // Clear the last element just in case
            memset(&users[SOCKS5_MAX_USERS - 1], 0, sizeof(struct socks5_user));
            users_count--;
            return 0;
        }
    }
    return -1;
}

/** ¿el servidor exige autenticación usuario/contraseña? */
static bool
socks5_auth_required(void) {
    return users_count > 0;
}

/** valida credenciales contra la tabla de usuarios */
static bool
socks5_check_credentials(const char *user, const char *pass) {
    for (unsigned i = 0; i < users_count; i++) {
        if (users[i].in_use &&
            strcmp(users[i].user, user) == 0 &&
            strcmp(users[i].pass, pass) == 0) {
            return true;
        }
    }
    return false;
}

////////////////////////////////////////////////////////////////////
// Pool de objetos y ciclo de vida

static const unsigned  max_pool  = 50;
static unsigned        pool_size = 0;
static struct socks5  *pool      = NULL;

/** conexiones SOCKS5 vivas; usado para el graceful shutdown */
static unsigned        current_connections = 0;
static unsigned long long historical_connections = 0;
static unsigned long long bytes_transferred = 0;

unsigned
socksv5_active_connections(void) {
    return current_connections;
}

unsigned long long
socksv5_historical_connections(void) {
    return historical_connections;
}

unsigned long long
socksv5_bytes_transferred(void) {
    return bytes_transferred;
}

/** crea (o recicla del pool) el estado de una nueva conexión SOCKS5 */
static struct socks5 *
socks5_new(const int client_fd) {
    struct socks5 *ret;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret  = pool;
        pool = pool->next;
        pool_size--;
    }
    if (ret == NULL) {
        return NULL;
    }

    memset(ret, 0x00, sizeof(*ret));
    ret->client_fd       = client_fd;
    ret->origin_fd       = -1;
    ret->client_addr_len = sizeof(ret->client_addr);
    strncpy(ret->client_username, "anonymous", sizeof(ret->client_username) - 1);
    ret->client_username[sizeof(ret->client_username) - 1] = '\0';

    buffer_init(&ret->read_buffer,  N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states    = client_statbl;
    stm_init(&ret->stm);

    ret->references = 1;
    current_connections++;
    historical_connections++;
    return ret;
}

/** libera definitivamente la estructura */
static void
socks5_destroy_(struct socks5 *s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = NULL;
    }
    free(s);
}

/**
 * Destruye un `struct socks5' teniendo en cuenta las referencias y el pool.
 * Solo libera/recicla cuando se sueltan todas las referencias.
 */
static void
socks5_destroy(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    if (s->references == 1) {
        current_connections--;
        // recursos por-conexión que NO deben sobrevivir al reuso por pool
        if (s->origin_resolution != NULL) {
            freeaddrinfo(s->origin_resolution);
            s->origin_resolution = NULL;
        }
        if (pool_size < max_pool) {
            s->next = pool;
            pool    = s;
            pool_size++;
        } else {
            socks5_destroy_(s);
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }
    pool      = NULL;
    pool_size = 0;
}

////////////////////////////////////////////////////////////////////
// Conexión pasiva

void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage  client_addr;
    socklen_t                client_addr_len = sizeof(client_addr);
    struct socks5           *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if (state == NULL) {
        // sin estado no podemos manejar la conexión
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return;
fail:
    if (client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////

/** callback por cada método ofrecido: elige según la política del servidor */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = p->data;

    if (socks5_auth_required()) {
        if (method == SOCKS_HELLO_USERNAME_PASSWORD) {
            *selected = SOCKS_HELLO_USERNAME_PASSWORD;
        }
    } else {
        if (method == SOCKS_HELLO_NOAUTHENTICATION_REQUIRED) {
            *selected = SOCKS_HELLO_NOAUTHENTICATION_REQUIRED;
        }
    }
}

static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct socks5   *s = ATTACHMENT(key);
    struct hello_st *d = &s->client.hello;

    d->rb     = &s->read_buffer;
    d->wb     = &s->write_buffer;
    d->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
    hello_parser_init(&d->parser);
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method;
}

/** arma la respuesta del hello en el buffer de escritura */
static unsigned
hello_process(struct hello_st *d) {
    if (hello_marshall(d->wb, d->method) == -1) {
        return ERROR;
    }
    return HELLO_WRITE;
}

static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d     = &ATTACHMENT(key)->client.hello;
    unsigned         ret   = HELLO_READ;
    bool             error = false;
    size_t           count;
    uint8_t         *ptr   = buffer_write_ptr(d->rb, &count);
    const ssize_t    n     = recv(key->fd, ptr, count, 0);

    if (n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if (hello_is_done(st, 0)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned
hello_write(struct selector_key *key) {
    struct hello_st *d   = &ATTACHMENT(key)->client.hello;
    unsigned         ret = HELLO_WRITE;
    size_t           count;
    uint8_t         *ptr = buffer_read_ptr(d->wb, &count);
    const ssize_t    n   = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            if (d->method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
                // ya informamos 0xFF; no hay método aceptable -> cerramos
                ret = DONE;
            } else if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = (d->method == SOCKS_HELLO_USERNAME_PASSWORD)
                        ? AUTH_READ
                        : REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }
    return ret;
}

////////////////////////////////////////////////////////////////////
// AUTH (usuario/contraseña, RFC 1929)
////////////////////////////////////////////////////////////////////

static void
auth_read_init(const unsigned state, struct selector_key *key) {
    struct socks5  *s = ATTACHMENT(key);
    struct auth_st *d = &s->client.auth;

    d->rb     = &s->read_buffer;
    d->wb     = &s->write_buffer;
    d->status = SOCKS_AUTH_FAILURE;
    auth_parser_init(&d->parser, &d->result);
}

static unsigned
auth_process(struct auth_st *d, struct socks5 *s) {
    d->status = socks5_check_credentials(d->result.username, d->result.password)
                  ? SOCKS_AUTH_SUCCESS
                  : SOCKS_AUTH_FAILURE;
    if (d->status == SOCKS_AUTH_SUCCESS) {
        strncpy(s->client_username, d->result.username,
                sizeof(s->client_username) - 1);
        s->client_username[sizeof(s->client_username) - 1] = '\0';
    }
    if (auth_marshall(d->wb, d->status) == -1) {
        return ERROR;
    }
    return AUTH_WRITE;
}

static unsigned
auth_read(struct selector_key *key) {
    struct auth_st *d     = &ATTACHMENT(key)->client.auth;
    unsigned        ret   = AUTH_READ;
    bool            error = false;
    size_t          count;
    uint8_t        *ptr   = buffer_write_ptr(d->rb, &count);
    const ssize_t   n     = recv(key->fd, ptr, count, 0);

    if (n > 0) {
        buffer_write_adv(d->rb, n);
        const enum auth_state st = auth_consume(d->rb, &d->parser, &error);
        if (auth_is_done(st, 0)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_process(d, ATTACHMENT(key));
            } else {
                ret = ERROR;
            }
        }
    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned
auth_write(struct selector_key *key) {
    struct auth_st *d   = &ATTACHMENT(key)->client.auth;
    unsigned        ret = AUTH_WRITE;
    size_t          count;
    uint8_t        *ptr = buffer_read_ptr(d->wb, &count);
    const ssize_t   n   = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            if (d->status == SOCKS_AUTH_SUCCESS &&
                SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = REQUEST_READ;
            } else {
                // autenticación fallida: ya enviamos el status, cerramos
                ret = DONE;
            }
        }
    }
    return ret;
}

////////////////////////////////////////////////////////////////////
// REQUEST
////////////////////////////////////////////////////////////////////

/** registra un acceso exitoso al destino en stdout (redirigible a archivo) */
static void
log_access(struct socks5 *s) {
    const time_t now = time(NULL);
    struct tm    tm_buf;
    char         timestamp[32];

    localtime_r(&now, &tm_buf);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);

    char dest_ip[SOCKADDR_TO_HUMAN_MIN];
    sockaddr_to_human(dest_ip, sizeof(dest_ip),
                      (const struct sockaddr *) &s->origin_addr);

    const char *fqdn = (s->dest_fqdn[0] != '\0') ? s->dest_fqdn : "-";

    fprintf(stdout, "[%s] User: %s | FQDN: %s | IP Destino: %s\n",
            timestamp, s->client_username, fqdn, dest_ip);
    fflush(stdout);
}

/** traduce un errno de connect() al código REP de SOCKS5 */
static uint8_t
errno_to_socks(const int e) {
    switch (e) {
        case 0:            return SOCKS_REP_SUCCESS;
        case ECONNREFUSED: return SOCKS_REP_CONN_REFUSED;
        case EHOSTUNREACH: return SOCKS_REP_HOST_UNREACHABLE;
        case ENETUNREACH:  return SOCKS_REP_NET_UNREACHABLE;
        case ETIMEDOUT:    return SOCKS_REP_TTL_EXPIRED;
        default:           return SOCKS_REP_GENERAL_FAILURE;
    }
}

static unsigned request_process    (struct selector_key *key);
static unsigned request_resolv     (struct selector_key *key);
static unsigned request_try_connect(struct selector_key *key);
static unsigned request_send_reply (struct selector_key *key);

static void
request_read_init(const unsigned state, struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;

    d->rb     = &s->read_buffer;
    d->wb     = &s->write_buffer;
    d->status = SOCKS_REP_GENERAL_FAILURE;
    request_parser_init(&d->parser, &d->result);
}

static unsigned
request_read(struct selector_key *key) {
    struct request_st *d     = &ATTACHMENT(key)->client.request;
    unsigned           ret   = REQUEST_READ;
    bool               error = false;
    size_t             count;
    uint8_t           *ptr   = buffer_write_ptr(d->rb, &count);
    const ssize_t      n     = recv(key->fd, ptr, count, 0);

    if (n > 0) {
        buffer_write_adv(d->rb, n);
        const enum request_state st = request_consume(d->rb, &d->parser, &error);
        if (request_is_done(st, 0)) {
            ret = request_process(key);
        }
    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        // ante un corte limpiamos lo que el parser pudo haber alocado
        request_parser_close(&d->parser);
        ret = ERROR;
    }

    return ret;
}

/** decide qué hacer una vez parseado el request */
static unsigned
request_process(struct selector_key *key) {
    struct socks5     *s  = ATTACHMENT(key);
    struct request_st *d  = &s->client.request;
    const enum request_state st = d->parser.state;

    if (st != REQUEST_DONE) {
        switch (st) {
            case REQUEST_ERROR_CMD:  d->status = SOCKS_REP_CMD_NOT_SUPPORTED;  break;
            case REQUEST_ERROR_ATYP: d->status = SOCKS_REP_ATYP_NOT_SUPPORTED; break;
            default:                 d->status = SOCKS_REP_GENERAL_FAILURE;    break;
        }
        request_parser_close(&d->parser);
        return request_send_reply(key);
    }

    s->dest_port = d->result.port;  // host byte order

    switch (d->result.atyp) {
        case SOCKS_ATYP_IPV4: {
            struct sockaddr_in *sin = (struct sockaddr_in *) &s->origin_addr;
            *sin = d->result.dest.ipv4;
            sin->sin_port      = htons(s->dest_port);
            s->origin_domain   = AF_INET;
            s->origin_addr_len = sizeof(struct sockaddr_in);
            request_parser_close(&d->parser);
            return request_try_connect(key);
        }
        case SOCKS_ATYP_IPV6: {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &s->origin_addr;
            *sin6 = d->result.dest.ipv6;
            sin6->sin6_port    = htons(s->dest_port);
            s->origin_domain   = AF_INET6;
            s->origin_addr_len = sizeof(struct sockaddr_in6);
            request_parser_close(&d->parser);
            return request_try_connect(key);
        }
        case SOCKS_ATYP_DOMAIN:
            // copiamos el FQDN fuera de la unión y liberamos lo alocado por el
            // parser; el thread de DNS leerá s->dest_fqdn (estable).
            strncpy(s->dest_fqdn, d->result.dest.domain.name,
                    sizeof(s->dest_fqdn) - 1);
            s->dest_fqdn[sizeof(s->dest_fqdn) - 1] = '\0';
            request_parser_close(&d->parser);
            return request_resolv(key);
        default:
            d->status = SOCKS_REP_ATYP_NOT_SUPPORTED;
            request_parser_close(&d->parser);
            return request_send_reply(key);
    }
}

////////////////////////////////////////////////////////////////////
// REQUEST: resolución de nombres (getaddrinfo en un thread aparte)

/**
 * Hilo dedicado a resolver el FQDN. NO hace ninguna otra I/O: solo resuelve y
 * despierta al selector con selector_notify_block.
 */
static void *
request_resolv_blocking(void *data) {
    struct selector_key *key = (struct selector_key *) data;
    struct socks5       *s   = ATTACHMENT(key);

    pthread_detach(pthread_self());

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
        .ai_flags    = AI_PASSIVE,
    };
    char service[8];
    snprintf(service, sizeof(service), "%hu", s->dest_port);

    s->origin_resolution = NULL;
    getaddrinfo(s->dest_fqdn, service, &hints, &s->origin_resolution);

    selector_notify_block(key->s, key->fd);
    free(data);
    return NULL;
}

static unsigned
request_resolv(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    // dejamos de leer del cliente mientras resolvemos
    if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP)) {
        return ERROR;
    }

    struct selector_key *k = malloc(sizeof(*k));
    if (k == NULL) {
        s->client.request.status = SOCKS_REP_GENERAL_FAILURE;
        return request_send_reply(key);
    }
    memcpy(k, key, sizeof(*k));

    pthread_t tid;
    if (pthread_create(&tid, NULL, request_resolv_blocking, k) != 0) {
        free(k);
        s->client.request.status = SOCKS_REP_GENERAL_FAILURE;
        return request_send_reply(key);
    }
    return REQUEST_RESOLV;
}

/** el thread de DNS termino, arrancamos la conexión al origin */
static unsigned
request_resolv_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    if (s->origin_resolution == NULL) {
        s->client.request.status = SOCKS_REP_HOST_UNREACHABLE;
        return request_send_reply(key);
    }

    s->origin_resolution_current = s->origin_resolution;
    s->origin_domain   = s->origin_resolution->ai_family;
    s->origin_addr_len = s->origin_resolution->ai_addrlen;
    memcpy(&s->origin_addr, s->origin_resolution->ai_addr,
           s->origin_resolution->ai_addrlen);

    return request_try_connect(key);
}

////////////////////////////////////////////////////////////////////
// REQUEST: conexión al origin

/** avanza a la siguiente dirección resuelta (solo para FQDN) */
static bool
request_next_addr(struct socks5 *s) {
    if (s->origin_resolution_current == NULL ||
        s->origin_resolution_current->ai_next == NULL) {
        return false;
    }
    s->origin_resolution_current = s->origin_resolution_current->ai_next;
    s->origin_domain   = s->origin_resolution_current->ai_family;
    s->origin_addr_len = s->origin_resolution_current->ai_addrlen;
    memcpy(&s->origin_addr, s->origin_resolution_current->ai_addr,
           s->origin_resolution_current->ai_addrlen);
    return true;
}

/**
 * Crea un socket hacia s->origin_addr y lanza un connect no bloqueante.
 * @return 0 si la conexión quedó en progreso (origin_fd registrado en OP_WRITE);
 *         -1 si falló y el caller debe probar otra dirección o reportar error.
 */
static int
origin_connect(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    s->origin_fd = socket(s->origin_domain, SOCK_STREAM, IPPROTO_TCP);
    if (s->origin_fd < 0) {
        return -1;
    }
    if (selector_fd_set_nio(s->origin_fd) == -1) {
        goto fail;
    }
    if (connect(s->origin_fd, (const struct sockaddr *) &s->origin_addr,
                s->origin_addr_len) == -1 && errno != EINPROGRESS) {
        goto fail;
    }
    // mientras conectamos no leemos del cliente
    if (SELECTOR_SUCCESS != selector_set_interest(key->s, s->client_fd, OP_NOOP)) {
        goto fail;
    }
    if (SELECTOR_SUCCESS != selector_register(key->s, s->origin_fd,
                                              &socks5_handler, OP_WRITE, s)) {
        goto fail;
    }
    s->references += 1;
    return 0;
fail:
    close(s->origin_fd);
    s->origin_fd = -1;
    return -1;
}

/** intenta conectar a la dirección actual y a las siguientes si fallan */
static unsigned
request_try_connect(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    do {
        if (origin_connect(key) == 0) {
            return REQUEST_CONNECTING;
        }
    } while (request_next_addr(s));

    s->client.request.status = errno_to_socks(errno);
    return request_send_reply(key);
}

/** se disparó el evento de escritura sobre el origin: chequea el connect */
static unsigned
request_connecting(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    if (key->fd != s->origin_fd) {
        return REQUEST_CONNECTING;
    }

    int       err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(s->origin_fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1) {
        err = errno ? errno : ECONNREFUSED;
    }
    if (err == 0) {
        s->client.request.status = SOCKS_REP_SUCCESS;
        log_access(s);
        return request_send_reply(key);
    }

    // esta dirección falló: la soltamos y probamos otra (robustez ante FQDN
    // que resuelve a varias IPs)
    selector_unregister_fd(key->s, s->origin_fd);  // decrementa references
    close(s->origin_fd);
    s->origin_fd = -1;

    if (request_next_addr(s)) {
        return request_try_connect(key);
    }
    s->client.request.status = errno_to_socks(err);
    return request_send_reply(key);
}

/** arma la respuesta del request en el write buffer y la deja lista para enviar */
static unsigned
request_send_reply(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;

    // ya no necesitamos la resolución
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution         = NULL;
        s->origin_resolution_current = NULL;
    }

    // dirección local del socket origin para BND.ADDR (best effort)
    struct sockaddr_storage bnd;
    socklen_t               bnd_len = sizeof(bnd);
    const struct sockaddr  *bnd_ptr = NULL;
    if (d->status == SOCKS_REP_SUCCESS && s->origin_fd != -1 &&
        getsockname(s->origin_fd, (struct sockaddr *) &bnd, &bnd_len) == 0) {
        bnd_ptr = (const struct sockaddr *) &bnd;
    } else {
        bnd_len = 0;
    }

    if (request_marshall(&s->write_buffer, d->status, bnd_ptr, bnd_len) == -1) {
        return ERROR;
    }

    // queremos escribirle la respuesta al cliente
    if (SELECTOR_SUCCESS != selector_set_interest(key->s, s->client_fd, OP_WRITE)) {
        return ERROR;
    }
    if (s->origin_fd != -1) {
        selector_set_interest(key->s, s->origin_fd, OP_NOOP);
    }
    return REQUEST_WRITE;
}

static unsigned
request_write(struct selector_key *key) {
    struct socks5     *s   = ATTACHMENT(key);
    struct request_st *d   = &s->client.request;
    unsigned           ret = REQUEST_WRITE;

    if (key->fd != s->client_fd) {
        return REQUEST_WRITE;
    }

    size_t        count;
    uint8_t      *ptr = buffer_read_ptr(&s->write_buffer, &count);
    const ssize_t n   = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(&s->write_buffer, n);
        if (!buffer_can_read(&s->write_buffer)) {
            ret = (d->status == SOCKS_REP_SUCCESS) ? COPY : DONE;
        }
    }
    return ret;
}

////////////////////////////////////////////////////////////////////
// COPY (túnel bidireccional)
////////////////////////////////////////////////////////////////////

/** devuelve la mitad del túnel correspondiente al fd que disparó el evento */
static struct copy *
copy_ptr(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct copy   *d = &s->client.copy;
    if (*d->fd != key->fd) {
        d = &s->orig.copy;
    }
    return d;
}

/** recalcula y aplica los intereses de una mitad según sus buffers/duplex */
static fd_interest
copy_compute_interests(fd_selector s, struct copy *d) {
    fd_interest interest = OP_NOOP;
    if ((d->duplex & OP_READ) && buffer_can_write(d->rb)) {
        interest |= OP_READ;
    }
    if ((d->duplex & OP_WRITE) && buffer_can_read(d->wb)) {
        interest |= OP_WRITE;
    }
    if (*d->fd != -1) {
        selector_set_interest(s, *d->fd, interest);
    }
    return interest;
}

static void
copy_init(const unsigned state, struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    struct copy *d = &s->client.copy;
    d->fd     = &s->client_fd;
    d->rb     = &s->read_buffer;   // lo que el cliente envía -> hacia el origin
    d->wb     = &s->write_buffer;  // lo que el origin envía  -> hacia el cliente
    d->duplex = OP_READ | OP_WRITE;
    d->other  = &s->orig.copy;

    d = &s->orig.copy;
    d->fd     = &s->origin_fd;
    d->rb     = &s->write_buffer;
    d->wb     = &s->read_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other  = &s->client.copy;

    copy_compute_interests(key->s, &s->client.copy);
    copy_compute_interests(key->s, &s->orig.copy);
}

/**
 * Intenta vaciar el write-buffer de una mitad hacia su fd sin esperar a
 * select(OP_WRITE). Si no puede escribir todo (parcial / EAGAIN), el resto
 * queda en el buffer y copy_compute_interests suscribirá OP_WRITE.
 * @return true si el peer sigue pudiendo escribir; false si hubo error fatal.
 */
static bool
copy_try_flush(struct copy *peer) {
    if (*peer->fd == -1 || !(peer->duplex & OP_WRITE) ||
        !buffer_can_read(peer->wb)) {
        return true;
    }

    size_t   size;
    uint8_t *ptr = buffer_read_ptr(peer->wb, &size);
    const ssize_t n = send(*peer->fd, ptr, size, MSG_NOSIGNAL);

    if (n >= 0) {
        buffer_read_adv(peer->wb, n);
        if (n > 0) {
            bytes_transferred += n;
        }
        return true;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return true;
    }
    peer->duplex &= ~OP_WRITE;
    shutdown(*peer->fd, SHUT_WR);
    return false;
}

/**
 * Propaga cierres parciales y decide si terminamos.
 * Si una mitad dejó de leer y su buffer ya está vacío, no llegará más data al
 * otro lado: cerramos su escritura. Cuando ambas mitades quedan sin intereses,
 * el túnel terminó.
 */
static unsigned
copy_after(struct selector_key *key, struct copy *d) {
    if (!(d->duplex & OP_READ) && !buffer_can_read(d->rb) &&
        (d->other->duplex & OP_WRITE)) {
        d->other->duplex &= ~OP_WRITE;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_WR);
        }
    }
    if (!(d->other->duplex & OP_READ) && !buffer_can_read(d->other->rb) &&
        (d->duplex & OP_WRITE)) {
        d->duplex &= ~OP_WRITE;
        if (*d->fd != -1) {
            shutdown(*d->fd, SHUT_WR);
        }
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);

    if (d->duplex == OP_NOOP && d->other->duplex == OP_NOOP) {
        return DONE;
    }
    return COPY;
}

static unsigned
copy_read(struct selector_key *key) {
    struct copy  *d   = copy_ptr(key);
    size_t        size;
    uint8_t      *ptr  = buffer_write_ptr(d->rb, &size);
    const ssize_t n    = recv(key->fd, ptr, size, 0);

    if (n > 0) {
        buffer_write_adv(d->rb, n);
        bytes_transferred += n;
        /* Optimistic write: select -> read -> write (sin select intermedio) */
        copy_try_flush(d->other);
    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        // EOF o error de lectura: cerramos la mitad de lectura
        d->duplex &= ~OP_READ;
        shutdown(*d->fd, SHUT_RD);
    }
    return copy_after(key, d);
}

static unsigned
copy_write(struct selector_key *key) {
    struct copy *d = copy_ptr(key);
    copy_try_flush(d);
    return copy_after(key, d);
}

////////////////////////////////////////////////////////////////////
// Handlers top-level: emiten los eventos del selector a la stm
////////////////////////////////////////////////////////////////////

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key *key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}
