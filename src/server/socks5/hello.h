#ifndef HELLO_H_1234567890abcdef
#define HELLO_H_1234567890abcdef

/**
 * hello.h - parser del mensaje HELLO de SOCKS5 (RFC 1928)
 *
 * El cliente envía:
 *   +----+----------+----------+
 *   |VER | NMETHODS | METHODS  |
 *   +----+----------+----------+
 *   | 1  |    1     | 1..255   |
 *   +----+----------+----------+
 *
 * El servidor responde:
 *   +----+--------+
 *   |VER | METHOD |
 *   +----+--------+
 *   | 1  |   1    |
 *   +----+--------+
 */

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define SOCKS_VERSION 0x05

/** Métodos de autenticación definidos en RFC 1928 */
#define SOCKS_HELLO_NOAUTHENTICATION_REQUIRED 0x00
#define SOCKS_HELLO_GSSAPI                    0x01
#define SOCKS_HELLO_USERNAME_PASSWORD         0x02
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS     0xFF

/** Estados del parser de HELLO */
enum hello_state {
    HELLO_VERSION,      // esperando VER
    HELLO_NMETHODS,     // esperando NMETHODS
    HELLO_METHODS,      // esperando los métodos
    HELLO_DONE,         // parsing completado exitosamente
    HELLO_ERROR_VER,    // versión incorrecta
    HELLO_ERROR,        // error general
};

/** Parser del mensaje HELLO */
struct hello_parser {
    enum hello_state state;
    uint8_t nmethods;           // cantidad de métodos esperados
    uint8_t methods_read;       // métodos leídos hasta ahora
    
    /** callback invocado por cada método de autenticación recibido */
    void (*on_authentication_method)(struct hello_parser *p, const uint8_t method);
    /** dato adjunto para el callback */
    void *data;
};

/**
 * Inicializa el parser de HELLO
 */
void
hello_parser_init(struct hello_parser *p);

/**
 * Alimenta el parser con un byte del mensaje HELLO.
 * Retorna el estado actual del parser.
 */
enum hello_state
hello_parser_feed(struct hello_parser *p, const uint8_t b);

/**
 * Consume bytes del buffer hasta que el parser complete o no haya más datos.
 * 
 * @param rb    buffer de lectura con los bytes recibidos
 * @param p     parser
 * @param error se setea a true si ocurre un error de parsing
 * @return estado actual del parser
 */
enum hello_state
hello_consume(buffer *rb, struct hello_parser *p, bool *error);

/**
 * Verifica si el parser llegó al estado DONE.
 * Si error != NULL, se setea a true si el estado es de error.
 */
bool
hello_is_done(const enum hello_state state, bool *error);

/**
 * Escribe la respuesta HELLO en el buffer de escritura.
 * 
 * @param wb      buffer de escritura
 * @param method  método de autenticación seleccionado
 * @return 0 si ok, -1 si error
 */
int
hello_marshall(buffer *wb, const uint8_t method);

#endif