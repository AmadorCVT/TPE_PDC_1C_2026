#ifndef REQUEST_H_
#define REQUEST_H_

/**
 * request.h - parser del mensaje REQUEST de SOCKS5 (RFC 1928)
 *
 * El cliente envía:
 *   +----+-----+-------+------+----------+----------+
 *   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *   +----+-----+-------+------+----------+----------+
 *   | 1  |  1  | X'00' |  1   | variable |    2     |
 *   +----+-----+-------+------+----------+----------+
 *
 * El servidor responde:
 *   +----+-----+-------+------+----------+----------+
 *   |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *   +----+-----+-------+------+----------+----------+
 *   | 1  |  1  | X'00' |  1   | variable |    2     |
 *   +----+-----+-------+------+----------+----------+
 */

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>

#include "buffer.h"

/** Comandos SOCKS5 */
#define SOCKS_CMD_CONNECT       0x01
#define SOCKS_CMD_BIND          0x02
#define SOCKS_CMD_UDP_ASSOCIATE 0x03

/** Tipos de dirección (ATYP) */
#define SOCKS_ATYP_IPV4   0x01
#define SOCKS_ATYP_DOMAIN 0x03
#define SOCKS_ATYP_IPV6   0x04

/** Códigos de respuesta (REP) */
#define SOCKS_REP_SUCCESS            0x00
#define SOCKS_REP_GENERAL_FAILURE    0x01
#define SOCKS_REP_NOT_ALLOWED        0x02
#define SOCKS_REP_NET_UNREACHABLE    0x03
#define SOCKS_REP_HOST_UNREACHABLE   0x04
#define SOCKS_REP_CONN_REFUSED       0x05
#define SOCKS_REP_TTL_EXPIRED        0x06
#define SOCKS_REP_CMD_NOT_SUPPORTED  0x07
#define SOCKS_REP_ATYP_NOT_SUPPORTED 0x08

/** Estados del parser de REQUEST */
enum request_state {
    REQUEST_VERSION,        // esperando VER
    REQUEST_CMD,            // esperando CMD
    REQUEST_RSV,            // esperando RSV
    REQUEST_ATYP,           // esperando ATYP
    REQUEST_DST_ADDR,       // esperando DST.ADDR
    REQUEST_DST_PORT,       // esperando DST.PORT
    REQUEST_DONE,           // parsing completado
    REQUEST_ERROR_VER,      // versión incorrecta
    REQUEST_ERROR_CMD,      // comando no soportado
    REQUEST_ERROR_ATYP,     // tipo de dirección no soportado
    REQUEST_ERROR,          // error general
};

/** Resultado del parsing del REQUEST */
struct request_result {
    uint8_t  cmd;           // comando solicitado
    uint8_t  atyp;          // tipo de dirección
    union {
        struct sockaddr_in  ipv4;
        struct sockaddr_in6 ipv6;
        struct {
            char *name;     // FQDN (malloqueado)
            uint8_t len;    // largo del FQDN
        } domain;
    } dest;
    uint16_t port;          // puerto destino (network byte order)
};

/** Parser del mensaje REQUEST */
struct request_parser {
    enum request_state state;
    struct request_result *result;
    
    // estado interno para parsing
    uint8_t domain_len;     // largo del FQDN (cuando ATYP es DOMAIN)
    uint8_t addr_bytes_read; // bytes de dirección leídos
    uint8_t port_bytes_read; // bytes de puerto leídos
    uint8_t port_buf[2];    // buffer temporal para el puerto
};

/**
 * Inicializa el parser de REQUEST
 * @param result estructura donde se guardará el resultado (debe persistir)
 */
void
request_parser_init(struct request_parser *p, struct request_result *result);

/**
 * Libera recursos alocados por el parser (ej: FQDN)
 */
void
request_parser_close(struct request_parser *p);

/**
 * Alimenta el parser con un byte.
 */
enum request_state
request_parser_feed(struct request_parser *p, const uint8_t b);

/**
 * Consume bytes del buffer hasta completar o error.
 */
enum request_state
request_consume(buffer *rb, struct request_parser *p, bool *error);

/**
 * Verifica si el parser terminó.
 */
bool
request_is_done(const enum request_state state, bool *error);

/**
 * Escribe la respuesta REQUEST en el buffer.
 * 
 * @param wb        buffer de escritura
 * @param rep       código de respuesta
 * @param bind_addr dirección local del socket origin (para BND.ADDR)
 * @param bind_len  largo de bind_addr
 * @return 0 si ok, -1 si error
 */
int
request_marshall(buffer *wb, uint8_t rep,
                 const struct sockaddr *bind_addr, socklen_t bind_len);

#endif