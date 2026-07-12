/**
 * main.c - servidor proxy SOCKS5 (sockets no bloqueantes)
 *
 * Interpreta los argumentos de línea de comandos, monta un socket pasivo
 * y delega cada conexión entrante a la máquina de estados de socks5nio.
 *
 * Todas las conexiones se manejan en este único hilo mediante el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <arpa/inet.h>   // inet_pton

#include "selector.h"
#include "args.h"
#include "socks5nio.h"
#include "mng_server.h"

static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t force_shutdown     = 0;

static void
sigterm_handler(const int signal) {
    if(shutdown_requested) {
        force_shutdown = 1;
    } else {
        shutdown_requested = 1;
    }
}

int
main(const int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);

    // cargamos los usuarios habilitados para autenticación usuario/contraseña
    for(unsigned i = 0; i < MAX_USERS; i++) {
        if(args.users[i].name != NULL && args.users[i].pass != NULL) {
            if(!socks5_add_user(args.users[i].name, args.users[i].pass)) {
                fprintf(stderr, "could not register user: %s\n",
                        args.users[i].name);
            }
        }
    }

    // no tenemos nada que leer de stdin
    close(0);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector       selector = NULL;
    int               server   = -1;
    int               mng_server = -1;

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(args.socks_port);
    if(args.socks_addr == NULL ||
       inet_pton(AF_INET6, args.socks_addr, &addr.sin6_addr) != 1) {
        addr.sin6_addr = in6addr_any;
    }

    server = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", args.socks_port);

    // man 7 ip. no importa reportar nada si falla.

    int v6only = 0;
    if(setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
        err_msg = "unable to set IPV6_ONLY option";
        goto finally;
    }

    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if(listen(server, SOMAXCONN) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler socksv5 = {
        .handle_read  = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL, // el socket pasivo no aloca nada
    };
    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    mng_server = mng_server_init(args.mng_addr, args.mng_port, selector, args.mng_secret);
    if(mng_server < 0) {
        err_msg = "unable to initialize management server";
        goto finally;
    }
    fprintf(stdout, "Management listening on TCP port %d\n", args.mng_port);
    if(strcmp(args.mng_secret, "changeme") == 0) {
        fprintf(stderr, "warning: using default management secret 'changeme', set one with -A\n");
    }

    bool draining = false;
    while(!force_shutdown) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }

        if(shutdown_requested && !draining) {
            draining = true;
            // dejamos de aceptar nuevas conexiones y drenamos las vivas
            selector_unregister_fd(selector, server);
            close(server);
            server = -1;

            if(mng_server >= 0) {
                selector_unregister_fd(selector, mng_server);
                close(mng_server);
                mng_server = -1;
            }

            fprintf(stdout, "graceful shutdown: no se aceptan nuevas conexiones, "
                            "esperando %u conexiones activas\n",
                    socksv5_active_connections());
        }
        if(draining && socksv5_active_connections() == 0) {
            break;
        }
    }
    // salida limpia del loop (drenaje completo o apagado forzoso)

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    socksv5_pool_destroy();

    if(server >= 0) {
        close(server);
    }
    if(mng_server >= 0) {
        close(mng_server);
    }
    return ret;
}
