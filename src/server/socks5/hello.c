/**
 * hello.c - implementación del parser del mensaje HELLO de SOCKS5
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "hello.h"

void
hello_parser_init(struct hello_parser *p) {
    p->state       = HELLO_VERSION;
    p->nmethods    = 0;
    p->methods_read = 0;
    p->on_authentication_method = NULL;
    p->data        = NULL;
}

enum hello_state
hello_parser_feed(struct hello_parser *p, const uint8_t b) {
    switch (p->state) {
    case HELLO_VERSION:
        if (b == SOCKS_VERSION) {
            p->state = HELLO_NMETHODS;
        } else {
            p->state = HELLO_ERROR_VER;
        }
        break;

    case HELLO_NMETHODS:
        if (b == 0) {
            // NMETHODS no puede ser 0 según RFC 1928
            p->state = HELLO_ERROR;
        } else {
            p->nmethods = b;
            p->methods_read = 0;
            p->state = HELLO_METHODS;
        }
        break;

    case HELLO_METHODS:
        if (p->on_authentication_method != NULL) {
            p->on_authentication_method(p, b);
        }
        p->methods_read++;
        if (p->methods_read >= p->nmethods) {
            p->state = HELLO_DONE;
        }
        break;

    case HELLO_DONE:
    case HELLO_ERROR_VER:
    case HELLO_ERROR:
        // No deberíamos recibir más bytes en estos estados
        break;
    }

    return p->state;
}

enum hello_state
hello_consume(buffer *rb, struct hello_parser *p, bool *error) {
    enum hello_state st = p->state;

    while (!hello_is_done(st, error) && buffer_can_read(rb)) {
        const uint8_t c = buffer_read(rb);
        st = hello_parser_feed(p, c);
    }
    return st;
}

bool
hello_is_done(const enum hello_state state, bool *error) {
    if (error != NULL) {
        *error = (state == HELLO_ERROR_VER || state == HELLO_ERROR);
    }
    return state == HELLO_DONE || state == HELLO_ERROR_VER || state == HELLO_ERROR;
}

int
hello_marshall(buffer *wb, const uint8_t method) {
    size_t n;
    uint8_t *ptr = buffer_write_ptr(wb, &n);
    
    if (n < 2) {
        return -1;
    }
    
    ptr[0] = SOCKS_VERSION;
    ptr[1] = method;
    buffer_write_adv(wb, 2);
    
    return 0;
}