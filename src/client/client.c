#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
    memset(cmd_str, 0, sizeof(cmd_str));

    if (strcmp(argv[optind], "get-metrics") == 0) {
        if (optind + 1 < argc) {
            print_usage(argv[0]);
            return 1;
        }
        snprintf(cmd_str, sizeof(cmd_str), "%s GET_METRICS\n", mng_secret);
    } else if (strcmp(argv[optind], "add-user") == 0) {
        if (optind + 3 != argc) {
            print_usage(argv[0]);
            return 1;
        }
        snprintf(cmd_str, sizeof(cmd_str), "%s ADD_USER %s %s\n", mng_secret, argv[optind + 1], argv[optind + 2]);
    } else if (strcmp(argv[optind], "del-user") == 0) {
        if (optind + 2 != argc) {
            print_usage(argv[0]);
            return 1;
        }
        snprintf(cmd_str, sizeof(cmd_str), "%s DEL_USER %s\n", mng_secret, argv[optind + 1]);
    } else if (strcmp(argv[optind], "set-secret") == 0) {
        if (optind + 2 != argc) {
            print_usage(argv[0]);
            return 1;
        }
        snprintf(cmd_str, sizeof(cmd_str), "%s SET_SECRET %s\n", mng_secret, argv[optind + 1]);
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

    char recv_buf[1024];
    ssize_t n;
    while ((n = recv(sock, recv_buf, sizeof(recv_buf) - 1, 0)) > 0) {
        recv_buf[n] = '\0';
        printf("%s", recv_buf);
    }

    if (n < 0) {
        perror("recv failed");
        close(sock);
        return 1;
    }

    close(sock);
    return 0;
}
