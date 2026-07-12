#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum client_cmd {
    CMD_GET_METRICS,
    CMD_ADD_USER,
    CMD_DEL_USER,
    CMD_SET_SECRET,
};

static void
print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [options] <command>\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -L <address>   IP address of management server (default: 127.0.0.1)\n");
    fprintf(stderr, "  -P <port>      Port of management server (default: 8080)\n");
    fprintf(stderr, "  -A <secret>    Management protocol secret (default: changeme)\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  get-metrics\n");
    fprintf(stderr, "  add-user <username> <password>\n");
    fprintf(stderr, "  del-user <username>\n");
    fprintf(stderr, "  set-secret <new_secret>  (uses -A as the current secret)\n");
}

/**
 * Lee una línea de respuesta terminada en CRLF (o LF).
 * @return 0 ok, -1 error de red/EOF prematuro, -2 línea demasiado larga
 */
static int
recv_line(int sock, char *buf, size_t buflen) {
    size_t used = 0;

    while (used + 1 < buflen) {
        char c;
        ssize_t n = recv(sock, &c, 1, 0);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            return used == 0 ? -1 : 0;
        }
        if (c == '\n') {
            if (used > 0 && buf[used - 1] == '\r') {
                used--;
            }
            buf[used] = '\0';
            return 0;
        }
        buf[used++] = c;
    }
    return -2;
}

static int
print_response(enum client_cmd cmd, const char *line) {
    if (strncmp(line, "+OK", 3) == 0) {
        const char *rest = line + 3;
        while (*rest == ' ') {
            rest++;
        }

        switch (cmd) {
            case CMD_GET_METRICS: {
                unsigned long act = 0, hist = 0, bytes = 0;
                if (sscanf(rest, "ACT:%lu HIST:%lu BYTES:%lu",
                           &act, &hist, &bytes) == 3) {
                    printf("conexiones activas: %lu\n", act);
                    printf("conexiones historicas: %lu\n", hist);
                    printf("bytes transferidos: %lu\n", bytes);
                } else if (*rest == '\0') {
                    printf("OK\n");
                } else {
                    printf("OK %s\n", rest);
                }
                break;
            }
            case CMD_ADD_USER:
                printf("usuario agregado\n");
                break;
            case CMD_DEL_USER:
                printf("usuario eliminado\n");
                break;
            case CMD_SET_SECRET:
                printf("secreto actualizado\n");
                break;
        }
        return 0;
    }

    if (strncmp(line, "-ERR", 4) == 0) {
        const char *rest = line + 4;
        while (*rest == ' ') {
            rest++;
        }
        if (*rest != '\0') {
            fprintf(stderr, "error: %s\n", rest);
        } else {
            fprintf(stderr, "error: comando rechazado\n");
        }
        return 1;
    }

    fprintf(stderr, "error: respuesta inesperada: %s\n", line);
    return 1;
}

int
main(int argc, char **argv) {
    char *mng_addr = "127.0.0.1";
    unsigned short mng_port = 8080;
    char *mng_secret = "changeme";

    int c;
    while ((c = getopt(argc, argv, "L:P:A:")) != -1) {
        switch (c) {
            case 'L':
                mng_addr = optarg;
                break;
            case 'P': {
                char *endptr;
                long port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || port <= 0 || port > 65535) {
                    fprintf(stderr, "invalid port: %s\n", optarg);
                    return 1;
                }
                mng_port = (unsigned short)port;
                break;
            }
            case 'A':
                mng_secret = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    char cmd_str[1024];
    enum client_cmd cmd;
    memset(cmd_str, 0, sizeof(cmd_str));

    if (strcmp(argv[optind], "get-metrics") == 0) {
        if (optind + 1 < argc) {
            print_usage(argv[0]);
            return 1;
        }
        cmd = CMD_GET_METRICS;
        snprintf(cmd_str, sizeof(cmd_str), "%s GET_METRICS\n", mng_secret);
    } else if (strcmp(argv[optind], "add-user") == 0) {
        if (optind + 3 != argc) {
            print_usage(argv[0]);
            return 1;
        }
        cmd = CMD_ADD_USER;
        snprintf(cmd_str, sizeof(cmd_str), "%s ADD_USER %s %s\n",
                 mng_secret, argv[optind + 1], argv[optind + 2]);
    } else if (strcmp(argv[optind], "del-user") == 0) {
        if (optind + 2 != argc) {
            print_usage(argv[0]);
            return 1;
        }
        cmd = CMD_DEL_USER;
        snprintf(cmd_str, sizeof(cmd_str), "%s DEL_USER %s\n",
                 mng_secret, argv[optind + 1]);
    } else if (strcmp(argv[optind], "set-secret") == 0) {
        if (optind + 2 != argc) {
            print_usage(argv[0]);
            return 1;
        }
        cmd = CMD_SET_SECRET;
        snprintf(cmd_str, sizeof(cmd_str), "%s SET_SECRET %s\n",
                 mng_secret, argv[optind + 1]);
    } else {
        print_usage(argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket creation failed");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(mng_port);
    if (inet_pton(AF_INET, mng_addr, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", mng_addr);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connection failed");
        close(sock);
        return 1;
    }

    size_t cmd_len = strlen(cmd_str);
    size_t sent = 0;
    while (sent < cmd_len) {
        ssize_t n = send(sock, cmd_str + sent, cmd_len - sent, 0);
        if (n <= 0) {
            perror("send failed");
            close(sock);
            return 1;
        }
        sent += n;
    }

    char line[1024];
    int rc = recv_line(sock, line, sizeof(line));
    if (rc == -2) {
        fprintf(stderr, "error: respuesta demasiado larga\n");
        close(sock);
        return 1;
    }
    if (rc < 0) {
        fprintf(stderr, "error: no se recibio respuesta del servidor\n");
        close(sock);
        return 1;
    }

    int exit_code = print_response(cmd, line);
    close(sock);
    return exit_code;
}
