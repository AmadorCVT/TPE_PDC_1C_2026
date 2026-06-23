#ifndef AUTH_H_
#define AUTH_H_

/**
 * auth.h - parser de autenticación USER/PASSWORD (RFC 1929)
 *
 * El cliente envía:
 *   +----+------+----------+------+----------+
 *   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *   +----+------+----------+------+----------+
 *   | 1  |  1   | 1..255   |  1   | 1..255   |
 *   +----+------+----------+------+----------+
 *
 * El servidor responde:
 *   +----+--------+
 *   |VER | STATUS |
 *   +----+--------+
 *   | 1  |   1    |
 *   +----+--------+
 */

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define SOCKS_AUTH_VERSION 0x01
#define SOCKS_AUTH_SUCCESS 0x00
#define SOCKS_AUTH_FAILURE 0x01

/** Estados del parser de autenticación */
enum auth_state {
    AUTH_VERSION,       // esperando VER
    AUTH_ULEN,          // esperando ULEN
    AUTH_UNAME,         // esperando UNAME
    AUTH_PLEN,          // esperando PLEN
    AUTH_PASSWD,        // esperando PASSWD
    AUTH_DONE,          // parsing completado
    AUTH_ERROR_VER,     // versión incorrecta
    AUTH_ERROR,         // error general
};

/** Resultado del parsing de autenticación */
struct auth_result {
    char username[256];  // username (max 255 + null)
    char password[256];  // password (max 255 + null)
    uint8_t ulen;        // largo del username
    uint8_t plen;        // largo del password
};

/** Parser de autenticación */
struct auth_parser {
    enum auth_state state;
    struct auth_result *result;
    
    uint8_t bytes_read;  // bytes leídos del campo actual
};

/**
 * Inicializa el parser de autenticación
 */
void
auth_parser_init(struct auth_parser *p, struct auth_result *result);

/**
 * Alimenta el parser con un byte.
 */
enum auth_state
auth_parser_feed(struct auth_parser *p, const uint8_t b);

/**
 * Consume bytes del buffer hasta completar o error.
 */
enum auth_state
auth_consume(buffer *rb, struct auth_parser *p, bool *error);

/**
 * Verifica si el parser terminó.
 */
bool
auth_is_done(const enum auth_state state, bool *error);

/**
 * Escribe la respuesta de autenticación en el buffer.
 * 
 * @param wb     buffer de escritura
 * @param status 0x00 = éxito, 0x01 = fallo
 * @return 0 si ok, -1 si error
 */
int
auth_marshall(buffer *wb, const uint8_t status);

#endif