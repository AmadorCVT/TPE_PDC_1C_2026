/**
 * request.c - implementación del parser del mensaje REQUEST de SOCKS5
 */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "hello.h"
#include "request.h"

void
request_parser_init(struct request_parser *p, struct request_result *result) {
    p->state            = REQUEST_VERSION;
    p->result           = result;
    p->domain_len       = 0;
    p->addr_bytes_read  = 0;
    p->port_bytes_read  = 0;
    
    memset(result, 0, sizeof(*result));
}

void
request_parser_close(struct request_parser *p) {
    if (p->result != NULL && p->result->atyp == SOCKS_ATYP_DOMAIN) {
        free(p->result->dest.domain.name);
        p->result->dest.domain.name = NULL;
    }
}

enum request_state
request_parser_feed(struct request_parser *p, const uint8_t b) {
    switch (p->state) {
    case REQUEST_VERSION:
        if (b == SOCKS_VERSION) {
            p->state = REQUEST_CMD;
        } else {
            p->state = REQUEST_ERROR_VER;
        }
        break;

    case REQUEST_CMD:
        p->result->cmd = b;
        if (b == SOCKS_CMD_CONNECT) {
            p->state = REQUEST_RSV;
        } else {
            // Solo soportamos CONNECT
            p->state = REQUEST_ERROR_CMD;
        }
        break;

    case REQUEST_RSV:
        if (b == 0x00) {
            p->state = REQUEST_ATYP;
        } else {
            p->state = REQUEST_ERROR;
        }
        break;

    case REQUEST_ATYP:
        p->result->atyp = b;
        p->addr_bytes_read = 0;
        p->port_bytes_read = 0;
        
        switch (b) {
        case SOCKS_ATYP_IPV4:
            p->state = REQUEST_DST_ADDR;
            break;
        case SOCKS_ATYP_DOMAIN:
            p->state = REQUEST_DST_ADDR;
            break;
        case SOCKS_ATYP_IPV6:
            p->state = REQUEST_DST_ADDR;
            break;
        default:
            p->state = REQUEST_ERROR_ATYP;
        }
        break;

    case REQUEST_DST_ADDR:
        switch (p->result->atyp) {
        case SOCKS_ATYP_IPV4:
            // Leer 4 bytes de IPv4
            ((uint8_t*)&p->result->dest.ipv4.sin_addr)[p->addr_bytes_read] = b;
            p->addr_bytes_read++;
            if (p->addr_bytes_read >= 4) {
                p->result->dest.ipv4.sin_family = AF_INET;
                p->state = REQUEST_DST_PORT;
            }
            break;

        case SOCKS_ATYP_DOMAIN:
            if (p->addr_bytes_read == 0) {
                // Primer byte: largo del FQDN
                p->domain_len = b;
                p->result->dest.domain.name = malloc(b + 1);
                if (p->result->dest.domain.name == NULL) {
                    p->state = REQUEST_ERROR;
                    break;
                }
                p->result->dest.domain.len = b;
                p->result->dest.domain.name[0] = '\0';
                p->addr_bytes_read = 1;
            } else {
                // Leer los bytes del FQDN
                p->result->dest.domain.name[p->addr_bytes_read - 1] = (char)b;
                p->addr_bytes_read++;
                if (p->addr_bytes_read > p->domain_len) {
                    p->result->dest.domain.name[p->domain_len] = '\0';
                    p->state = REQUEST_DST_PORT;
                }
            }
            break;

        case SOCKS_ATYP_IPV6:
            // Leer 16 bytes de IPv6
            ((uint8_t*)&p->result->dest.ipv6.sin6_addr)[p->addr_bytes_read] = b;
            p->addr_bytes_read++;
            if (p->addr_bytes_read >= 16) {
                p->result->dest.ipv6.sin6_family = AF_INET6;
                p->state = REQUEST_DST_PORT;
            }
            break;
        }
        break;

    case REQUEST_DST_PORT:
        // Leer 2 bytes de puerto (network byte order)
        p->port_buf[p->port_bytes_read] = b;
        p->port_bytes_read++;
        if (p->port_bytes_read >= 2) {
            p->result->port = (p->port_buf[0] << 8) | p->port_buf[1];
            p->state = REQUEST_DONE;
        }
        break;

    case REQUEST_DONE:
    case REQUEST_ERROR_VER:
    case REQUEST_ERROR_CMD:
    case REQUEST_ERROR_ATYP:
    case REQUEST_ERROR:
        break;
    }

    return p->state;
}

enum request_state
request_consume(buffer *rb, struct request_parser *p, bool *error) {
    enum request_state st = p->state;

    while (buffer_can_read(rb) && !request_is_done(st, error)) {
        const uint8_t c = buffer_read(rb);
        st = request_parser_feed(p, c);
    }
    return st;
}

bool
request_is_done(const enum request_state state, bool *error) {
    if (error != NULL) {
        *error = (state == REQUEST_ERROR_VER || 
                  state == REQUEST_ERROR_CMD ||
                  state == REQUEST_ERROR_ATYP || 
                  state == REQUEST_ERROR);
    }
    return state == REQUEST_DONE || 
           state == REQUEST_ERROR_VER ||
           state == REQUEST_ERROR_CMD ||
           state == REQUEST_ERROR_ATYP || 
           state == REQUEST_ERROR;
}

/**
 * Escribe un sockaddr en formato SOCKS5 (ATYP + ADDR + PORT) en el buffer.
 * Helper usado por request_marshall.
 */
static int
marshall_addr(buffer *wb, const struct sockaddr *addr, socklen_t addr_len) {
    size_t n;
    uint8_t *ptr;
    
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        
        ptr = buffer_write_ptr(wb, &n);
        if (n < 7) return -1; // ATYP(1) + IPv4(4) + PORT(2)
        
        ptr[0] = SOCKS_ATYP_IPV4;
        memcpy(&ptr[1], &sin->sin_addr, 4);
        memcpy(&ptr[5], &sin->sin_port, 2);
        buffer_write_adv(wb, 7);
        
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        
        ptr = buffer_write_ptr(wb, &n);
        if (n < 19) return -1; // ATYP(1) + IPv6(16) + PORT(2)
        
        ptr[0] = SOCKS_ATYP_IPV6;
        memcpy(&ptr[1], &sin6->sin6_addr, 16);
        memcpy(&ptr[17], &sin6->sin6_port, 2);
        buffer_write_adv(wb, 19);
        
    } else {
        return -1;
    }
    
    return 0;
}

int
request_marshall(buffer *wb, uint8_t rep,
                 const struct sockaddr *bind_addr, socklen_t bind_len) {
    size_t n;
    uint8_t *ptr = buffer_write_ptr(wb, &n);
    
    // Necesitamos al menos VER(1) + REP(1) + RSV(1) + ATYP(1) = 4 bytes
    if (n < 4) return -1;
    
    ptr[0] = SOCKS_VERSION;
    ptr[1] = rep;
    ptr[2] = 0x00; // RSV
    // ATYP lo escribe marshall_addr
    buffer_write_adv(wb, 3);
    
    if (bind_addr != NULL && bind_len > 0) {
        if (marshall_addr(wb, bind_addr, bind_len) != 0) {
            return -1;
        }
    } else {
        // Si no hay bind_addr, usar 0.0.0.0:0 como fallback
        ptr = buffer_write_ptr(wb, &n);
        if (n < 7) return -1;
        ptr[0] = SOCKS_ATYP_IPV4;
        memset(&ptr[1], 0, 4); // 0.0.0.0
        memset(&ptr[5], 0, 2); // port 0
        buffer_write_adv(wb, 7);
    }
    
    return 0;
}