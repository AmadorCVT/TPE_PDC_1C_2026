#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mng_server.h"
#include "selector.h"
#include "stm.h"
#include "buffer.h"
#include "socks5nio.h"

#define MNG_BUFFER_SIZE 1024

enum mng_state {
    MNG_READ = 0,
    MNG_EXECUTE,
    MNG_WRITE,
    MNG_DONE,
    MNG_ERROR
};

struct mng_connection {
    int client_fd;
    uint8_t raw_buff_read[MNG_BUFFER_SIZE];
    uint8_t raw_buff_write[MNG_BUFFER_SIZE];
    buffer read_buffer;
    buffer write_buffer;
    struct state_machine stm;
};

static char mng_secret[256];

#define ATTACHMENT(key) ((struct mng_connection *)(key)->data)

static void
mng_read_init(const unsigned state, struct selector_key *key) {
    // No initialization needed for MNG_READ
}

static unsigned
mng_read(struct selector_key *key) {
    struct mng_connection *conn = ATTACHMENT(key);
    size_t size;
    uint8_t *ptr = buffer_write_ptr(&conn->read_buffer, &size);
    if (size == 0) {
        return MNG_ERROR; // Buffer full without finding newline
    }

    const ssize_t n = recv(key->fd, ptr, size, 0);
    if (n > 0) {
        buffer_write_adv(&conn->read_buffer, n);

        // Search for newline
        size_t read_bytes;
        uint8_t *read_ptr = buffer_read_ptr(&conn->read_buffer, &read_bytes);
        for (size_t i = 0; i < read_bytes; i++) {
            if (read_ptr[i] == '\n') {
                return MNG_EXECUTE;
            }
        }
        return MNG_READ;
    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        return MNG_ERROR;
    }
    return MNG_READ;
}

static void
mng_execute_arrival(const unsigned state, struct selector_key *key) {
    struct mng_connection *conn = ATTACHMENT(key);

    size_t read_bytes;
    uint8_t *read_ptr = buffer_read_ptr(&conn->read_buffer, &read_bytes);

    size_t line_len = 0;
    size_t total_consumed = 0;
    for (size_t i = 0; i < read_bytes; i++) {
        if (read_ptr[i] == '\n') {
            line_len = i;
            total_consumed = i + 1;
            break;
        }
    }

    char line[MNG_BUFFER_SIZE];
    if (line_len >= MNG_BUFFER_SIZE) {
        snprintf((char *)conn->raw_buff_write, MNG_BUFFER_SIZE, "-ERR line too long\r\n");
        size_t response_len = strlen((char *)conn->raw_buff_write);
        buffer_write_adv(&conn->write_buffer, response_len);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    memcpy(line, read_ptr, line_len);
    line[line_len] = '\0';

    if (line_len > 0 && line[line_len - 1] == '\r') {
        line[line_len - 1] = '\0';
    }

    buffer_read_adv(&conn->read_buffer, total_consumed);

    char response[MNG_BUFFER_SIZE];
    memset(response, 0, sizeof(response));

    // cada línea empieza con el secreto de management; %n da el offset
    // donde terminó ese primer token, para poder ubicar el resto de la línea
    char provided_secret[256] = {0};
    int provided_len = 0;
    sscanf(line, "%255s%n", provided_secret, &provided_len);

    if (provided_len == 0 || strcmp(provided_secret, mng_secret) != 0) {
        snprintf(response, sizeof(response), "-ERR unauthorized\r\n");
    } else {
        const char *rest = line + provided_len;
        while (*rest == ' ') {
            rest++;
        }

        char cmd[128] = {0};
        int parsed = sscanf(rest, "%127s", cmd);
        if (parsed <= 0) {
            snprintf(response, sizeof(response), "-ERR empty command\r\n");
        } else if (strcmp(cmd, "GET_METRICS") == 0) {
            unsigned active = socksv5_active_connections();
            unsigned long long historical = socksv5_historical_connections();
            unsigned long long bytes = socksv5_bytes_transferred();
            snprintf(response, sizeof(response), "+OK ACT:%u HIST:%llu BYTES:%llu\r\n", active, historical, bytes);
        } else if (strcmp(cmd, "ADD_USER") == 0) {
            char username[256] = {0};
            char password[256] = {0};
            int n_args = sscanf(rest, "%*s %255s %255s", username, password);
            if (n_args == 2) {
                if (socks5_add_user(username, password)) {
                    snprintf(response, sizeof(response), "+OK\r\n");
                } else {
                    snprintf(response, sizeof(response), "-ERR unable to add user\r\n");
                }
            } else {
                snprintf(response, sizeof(response), "-ERR invalid arguments\r\n");
            }
        } else if (strcmp(cmd, "DEL_USER") == 0) {
            char username[256] = {0};
            int n_args = sscanf(rest, "%*s %255s", username);
            if (n_args == 1) {
                if (socks5_remove_user(username) == 0) {
                    snprintf(response, sizeof(response), "+OK\r\n");
                } else {
                    snprintf(response, sizeof(response), "-ERR user not found\r\n");
                }
            } else {
                snprintf(response, sizeof(response), "-ERR invalid arguments\r\n");
            }
        } else if (strcmp(cmd, "SET_SECRET") == 0) {
            char new_secret[256] = {0};
            int n_args = sscanf(rest, "%*s %255s", new_secret);
            if (n_args == 1) {
                strncpy(mng_secret, new_secret, sizeof(mng_secret) - 1);
                mng_secret[sizeof(mng_secret) - 1] = '\0';
                snprintf(response, sizeof(response), "+OK\r\n");
            } else {
                snprintf(response, sizeof(response), "-ERR invalid arguments\r\n");
            }
        } else {
            snprintf(response, sizeof(response), "-ERR unknown command\r\n");
        }
    }

    size_t resp_len = strlen(response);
    size_t write_avail;
    uint8_t *write_ptr = buffer_write_ptr(&conn->write_buffer, &write_avail);
    if (write_avail >= resp_len) {
        memcpy(write_ptr, response, resp_len);
        buffer_write_adv(&conn->write_buffer, resp_len);
    }
    
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned
mng_execute_write(struct selector_key *key) {
    return MNG_WRITE;
}

static unsigned
mng_write(struct selector_key *key) {
    struct mng_connection *conn = ATTACHMENT(key);
    size_t size;
    uint8_t *ptr = buffer_read_ptr(&conn->write_buffer, &size);
    if (size > 0) {
        const ssize_t n = send(key->fd, ptr, size, MSG_NOSIGNAL);
        if (n > 0) {
            buffer_read_adv(&conn->write_buffer, n);
            if (!buffer_can_read(&conn->write_buffer)) {
                return MNG_DONE;
            }
            return MNG_WRITE;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return MNG_ERROR;
        }
        return MNG_WRITE;
    }
    return MNG_DONE;
}

static const struct state_definition mng_statbl[] = {
    {
        .state         = MNG_READ,
        .on_arrival    = mng_read_init,
        .on_read_ready = mng_read,
    }, {
        .state         = MNG_EXECUTE,
        .on_arrival    = mng_execute_arrival,
        .on_write_ready = mng_execute_write,
    }, {
        .state         = MNG_WRITE,
        .on_write_ready = mng_write,
    }, {
        .state         = MNG_DONE,
    }, {
        .state         = MNG_ERROR,
    }
};

static void
mng_done(struct selector_key *key) {
    int fd = key->fd;
    selector_unregister_fd(key->s, fd);
    close(fd);
}

static void
mng_read_cb(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum mng_state st = stm_handler_read(stm, key);
    if (st == MNG_DONE || st == MNG_ERROR) {
        mng_done(key);
    }
}

static void
mng_write_cb(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum mng_state st = stm_handler_write(stm, key);
    if (st == MNG_DONE || st == MNG_ERROR) {
        mng_done(key);
    }
}

static void
mng_close_cb(struct selector_key *key) {
    struct mng_connection *conn = ATTACHMENT(key);
    if (conn != NULL) {
        free(conn);
    }
}

static const struct fd_handler mng_handler = {
    .handle_read   = mng_read_cb,
    .handle_write  = mng_write_cb,
    .handle_close  = mng_close_cb,
};

static void
mng_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    const int client = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client == -1) {
        return;
    }
    
    if (selector_fd_set_nio(client) == -1) {
        close(client);
        return;
    }
    
    struct mng_connection *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        close(client);
        return;
    }
    
    memset(conn, 0, sizeof(*conn));
    conn->client_fd = client;
    
    buffer_init(&conn->read_buffer, MNG_BUFFER_SIZE, conn->raw_buff_read);
    buffer_init(&conn->write_buffer, MNG_BUFFER_SIZE, conn->raw_buff_write);
    
    conn->stm.initial   = MNG_READ;
    conn->stm.max_state = MNG_ERROR;
    conn->stm.states    = mng_statbl;
    stm_init(&conn->stm);
    
    if (SELECTOR_SUCCESS != selector_register(key->s, client, &mng_handler, OP_READ, conn)) {
        close(client);
        free(conn);
    }
}

int
mng_server_init(const char *addr, unsigned port, fd_selector selector, const char *secret) {
    if (secret != NULL) {
        strncpy(mng_secret, secret, sizeof(mng_secret) - 1);
        mng_secret[sizeof(mng_secret) - 1] = '\0';
    }

    struct sockaddr_in addr_in;
    memset(&addr_in, 0, sizeof(addr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(port);
    if (addr == NULL || inet_pton(AF_INET, addr, &addr_in.sin_addr) != 1) {
        addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    
    int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        return -1;
    }
    
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    
    if (bind(server, (struct sockaddr *)&addr_in, sizeof(addr_in)) < 0) {
        close(server);
        return -1;
    }
    
    if (listen(server, SOMAXCONN) < 0) {
        close(server);
        return -1;
    }
    
    if (selector_fd_set_nio(server) == -1) {
        close(server);
        return -1;
    }
    
    static const struct fd_handler mng_server_handler = {
        .handle_read = mng_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
    };
    
    if (SELECTOR_SUCCESS != selector_register(selector, server, &mng_server_handler, OP_READ, NULL)) {
        close(server);
        return -1;
    }
    
    return server;
}
