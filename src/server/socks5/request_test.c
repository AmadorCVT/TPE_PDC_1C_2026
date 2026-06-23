/**
 * request_test.c - tests unitarios para el parser del mensaje REQUEST de SOCKS5
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>
#include <arpa/inet.h>

#include "request.h"
#include "buffer.h"

// Buffer de respaldo para pruebas
static uint8_t test_buff_data[512];
static buffer test_buff;

static void
setup_buffer(void) {
    buffer_init(&test_buff, sizeof(test_buff_data), test_buff_data);
}

// Helper: escribe bytes en el buffer de prueba
static void
feed_bytes(buffer *b, const uint8_t *bytes, size_t n) {
    size_t count;
    uint8_t *ptr = buffer_write_ptr(b, &count);
    ck_assert_uint_ge(count, n);
    memcpy(ptr, bytes, n);
    buffer_write_adv(b, n);
}

// ============================================================
// Tests: REQUEST IPv4 CONNECT
// ============================================================
START_TEST (test_request_ipv4_connect) {
    setup_buffer();

    // VER=0x05, CMD=0x01(CONNECT), RSV=0x00, ATYP=0x01(IPv4),
    // ADDR=192.168.1.1, PORT=0x1F90(8080)
    const uint8_t msg[] = {
        0x05, 0x01, 0x00, 0x01,
        0xC0, 0xA8, 0x01, 0x01,
        0x1F, 0x90
    };
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_uint_eq(SOCKS_CMD_CONNECT, result.cmd);
    ck_assert_uint_eq(SOCKS_ATYP_IPV4, result.atyp);
    ck_assert_uint_eq(8080, result.port);

    // Verificar dirección IPv4
    struct sockaddr_in expected;
    memset(&expected, 0, sizeof(expected));
    expected.sin_family = AF_INET;
    expected.sin_addr.s_addr = htonl(0xC0A80101);
    ck_assert_int_eq(0, memcmp(&expected.sin_addr,
                                &result.dest.ipv4.sin_addr, 4));

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST IPv6 CONNECT
// ============================================================
START_TEST (test_request_ipv6_connect) {
    setup_buffer();

    // VER=0x05, CMD=0x01(CONNECT), RSV=0x00, ATYP=0x04(IPv6),
    // ADDR=2001:db8::1, PORT=0x0050(80)
    const uint8_t msg[] = {
        0x05, 0x01, 0x00, 0x04,
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x50
    };
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_uint_eq(SOCKS_CMD_CONNECT, result.cmd);
    ck_assert_uint_eq(SOCKS_ATYP_IPV6, result.atyp);
    ck_assert_uint_eq(80, result.port);

    // Verificar dirección IPv6
    struct in6_addr expected;
    inet_pton(AF_INET6, "2001:db8::1", &expected);
    ck_assert_int_eq(0, memcmp(&expected, &result.dest.ipv6.sin6_addr, 16));

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST FQDN CONNECT
// ============================================================
START_TEST (test_request_fqdn_connect) {
    setup_buffer();

    // VER=0x05, CMD=0x01(CONNECT), RSV=0x00, ATYP=0x03(DOMAIN),
    // LEN=11, "example.com", PORT=0x0050(80)
    const uint8_t msg[] = {
        0x05, 0x01, 0x00, 0x03,
        0x0B,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x00, 0x50
    };
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_uint_eq(SOCKS_CMD_CONNECT, result.cmd);
    ck_assert_uint_eq(SOCKS_ATYP_DOMAIN, result.atyp);
    ck_assert_uint_eq(80, result.port);
    ck_assert_str_eq("example.com", result.dest.domain.name);
    ck_assert_uint_eq(11, result.dest.domain.len);

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST con versión incorrecta
// ============================================================
START_TEST (test_request_wrong_version) {
    setup_buffer();

    const uint8_t msg[] = {0x04, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_ERROR_VER, st);
    ck_assert_int_eq(true, error);

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST con comando no soportado (BIND)
// ============================================================
START_TEST (test_request_unsupported_cmd) {
    setup_buffer();

    // CMD=0x02 (BIND) - no soportado
    const uint8_t msg[] = {0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_ERROR_CMD, st);
    ck_assert_int_eq(true, error);

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST con ATYP no soportado
// ============================================================
START_TEST (test_request_unsupported_atyp) {
    setup_buffer();

    // ATYP=0x02 (no definido en RFC 1928)
    const uint8_t msg[] = {0x05, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_ERROR_ATYP, st);
    ck_assert_int_eq(true, error);

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST con RSV inválido
// ============================================================
START_TEST (test_request_invalid_rsv) {
    setup_buffer();

    // RSV=0x01 (debe ser 0x00)
    const uint8_t msg[] = {0x05, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    bool error = false;
    enum request_state st = request_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(REQUEST_ERROR, st);
    ck_assert_int_eq(true, error);

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Tests: REQUEST_MARSHALL con bind_addr IPv4
// ============================================================
START_TEST (test_request_marshall_ipv4) {
    setup_buffer();

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(0x7F000001); // 127.0.0.1
    bind_addr.sin_port = htons(1080);

    int ret = request_marshall(&test_buff, SOCKS_REP_SUCCESS,
                                (struct sockaddr *)&bind_addr,
                                sizeof(bind_addr));
    ck_assert_int_eq(0, ret);

    // Verificar: VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01,
    //           ADDR=127.0.0.1, PORT=1080
    ck_assert_uint_eq(0x05, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
    ck_assert_uint_eq(0x7F, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
    ck_assert_uint_eq(0x04, buffer_read(&test_buff)); // 1080 = 0x0438
    ck_assert_uint_eq(0x38, buffer_read(&test_buff));
}
END_TEST

// ============================================================
// Tests: REQUEST_MARSHALL con bind_addr NULL (fallback)
// ============================================================
START_TEST (test_request_marshall_null_addr) {
    setup_buffer();

    int ret = request_marshall(&test_buff, SOCKS_REP_GENERAL_FAILURE, NULL, 0);
    ck_assert_int_eq(0, ret);

    // Verificar: VER=0x05, REP=0x01, RSV=0x00, ATYP=0x01,
    //           ADDR=0.0.0.0, PORT=0
    ck_assert_uint_eq(0x05, buffer_read(&test_buff));
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
    // 0.0.0.0:0
    for (int i = 0; i < 6; i++) {
        ck_assert_uint_eq(0x00, buffer_read(&test_buff));
    }
}
END_TEST

// ============================================================
// Tests: consumo byte a byte (parcial)
// ============================================================
START_TEST (test_request_byte_by_byte) {
    struct request_result result;
    struct request_parser parser;
    request_parser_init(&parser, &result);

    // Alimentar byte a byte: IPv4 CONNECT a 1.2.3.4:80
    ck_assert_uint_eq(REQUEST_CMD,     request_parser_feed(&parser, 0x05));
    ck_assert_uint_eq(REQUEST_RSV,     request_parser_feed(&parser, 0x01));
    ck_assert_uint_eq(REQUEST_ATYP,    request_parser_feed(&parser, 0x00));
    ck_assert_uint_eq(REQUEST_DST_ADDR, request_parser_feed(&parser, 0x01));
    ck_assert_uint_eq(REQUEST_DST_ADDR, request_parser_feed(&parser, 0x01));
    ck_assert_uint_eq(REQUEST_DST_ADDR, request_parser_feed(&parser, 0x02));
    ck_assert_uint_eq(REQUEST_DST_ADDR, request_parser_feed(&parser, 0x03));
    ck_assert_uint_eq(REQUEST_DST_PORT, request_parser_feed(&parser, 0x04));
    ck_assert_uint_eq(REQUEST_DST_PORT, request_parser_feed(&parser, 0x00));
    ck_assert_uint_eq(REQUEST_DONE,    request_parser_feed(&parser, 0x50));

    ck_assert_uint_eq(SOCKS_CMD_CONNECT, result.cmd);
    ck_assert_uint_eq(SOCKS_ATYP_IPV4, result.atyp);
    ck_assert_uint_eq(80, result.port);

    request_parser_close(&parser);
}
END_TEST

// ============================================================
// Suite
// ============================================================
Suite *
request_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("socks5_request");

    tc = tcase_create("request_parser");
    tcase_add_test(tc, test_request_ipv4_connect);
    tcase_add_test(tc, test_request_ipv6_connect);
    tcase_add_test(tc, test_request_fqdn_connect);
    tcase_add_test(tc, test_request_wrong_version);
    tcase_add_test(tc, test_request_unsupported_cmd);
    tcase_add_test(tc, test_request_unsupported_atyp);
    tcase_add_test(tc, test_request_invalid_rsv);
    tcase_add_test(tc, test_request_byte_by_byte);
    suite_add_tcase(s, tc);

    tc = tcase_create("request_marshall");
    tcase_add_test(tc, test_request_marshall_ipv4);
    tcase_add_test(tc, test_request_marshall_null_addr);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = request_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
