/**
 * auth.c - implementación del parser de autenticación USER/PASSWORD (RFC 1929)
 */
#include <string.h>

#include "auth.h"

void
auth_parser_init(struct auth_parser *p, struct auth_result *result) {
    p->state       = AUTH_VERSION;
    p->result      = result;
    p->bytes_read  = 0;
    
    memset(result, 0, sizeof(*result));
}

enum auth_state
auth_parser_feed(struct auth_parser *p, const uint8_t b) {
    switch (p->state) {
    case AUTH_VERSION:
        if (b == SOCKS_AUTH_VERSION) {
            p->state = AUTH_ULEN;
        } else {
            p->state = AUTH_ERROR_VER;
        }
        break;

    case AUTH_ULEN:
        if (b == 0) {
            // ULEN no puede ser 0
            p->state = AUTH_ERROR;
        } else {
            p->result->ulen = b;
            p->bytes_read = 0;
            p->state = AUTH_UNAME;
        }
        break;

    case AUTH_UNAME:
        if (p->bytes_read < sizeof(p->result->username) - 1) {
            p->result->username[p->bytes_read] = (char)b;
        }
        p->bytes_read++;
        if (p->bytes_read >= p->result->ulen) {
            p->result->username[p->result->ulen] = '\0';
            p->state = AUTH_PLEN;
        }
        break;

    case AUTH_PLEN:
        if (b == 0) {
            // PLEN no puede ser 0
            p->state = AUTH_ERROR;
        } else {
            p->result->plen = b;
            p->bytes_read = 0;
            p->state = AUTH_PASSWD;
        }
        break;

    case AUTH_PASSWD:
        if (p->bytes_read < sizeof(p->result->password) - 1) {
            p->result->password[p->bytes_read] = (char)b;
        }
        p->bytes_read++;
        if (p->bytes_read >= p->result->plen) {
            p->result->password[p->result->plen] = '\0';
            p->state = AUTH_DONE;
        }
        break;

    case AUTH_DONE:
    case AUTH_ERROR_VER:
    case AUTH_ERROR:
        break;
    }

    return p->state;
}

enum auth_state
auth_consume(buffer *rb, struct auth_parser *p, bool *error) {
    enum auth_state st = p->state;

    while (buffer_can_read(rb) && !auth_is_done(st, error)) {
        const uint8_t c = buffer_read(rb);
        st = auth_parser_feed(p, c);
    }
    return st;
}

bool
auth_is_done(const enum auth_state state, bool *error) {
    if (error != NULL) {
        *error = (state == AUTH_ERROR_VER || state == AUTH_ERROR);
    }
    return state == AUTH_DONE || state == AUTH_ERROR_VER || state == AUTH_ERROR;
}

int
auth_marshall(buffer *wb, const uint8_t status) {
    size_t n;
    uint8_t *ptr = buffer_write_ptr(wb, &n);
    
    if (n < 2) {
        return -1;
    }
    
    ptr[0] = SOCKS_AUTH_VERSION;
    ptr[1] = status;
    buffer_write_adv(wb, 2);
    
    return 0;
}