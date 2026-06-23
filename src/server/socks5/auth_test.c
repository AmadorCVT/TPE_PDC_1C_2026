/**
 * auth_test.c - tests unitarios para el parser de autenticación USER/PASSWORD (RFC 1929)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "auth.h"
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
// Tests: AUTH válido
// ============================================================
START_TEST (test_auth_valid) {
    setup_buffer();

    // VER=0x01, ULEN=4, UNAME="test", PLEN=4, PASSWD="pass"
    const uint8_t msg[] = {
        0x01, 0x04,
        't', 'e', 's', 't',
        0x04,
        'p', 'a', 's', 's'
    };
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    bool error = false;
    enum auth_state st = auth_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(AUTH_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_str_eq("test", result.username);
    ck_assert_str_eq("pass", result.password);
    ck_assert_uint_eq(4, result.ulen);
    ck_assert_uint_eq(4, result.plen);
}
END_TEST

// ============================================================
// Tests: AUTH con username largo
// ============================================================
START_TEST (test_auth_long_username) {
    setup_buffer();

    // VER=0x01, ULEN=10, UNAME="username99", PLEN=4, PASSWD="pass"
    const uint8_t msg[] = {
        0x01, 0x0A,
        'u', 's', 'e', 'r', 'n', 'a', 'm', 'e', '9', '9',
        0x04,
        'p', 'a', 's', 's'
    };
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    bool error = false;
    enum auth_state st = auth_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(AUTH_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_str_eq("username99", result.username);
    ck_assert_str_eq("pass", result.password);
}
END_TEST

// ============================================================
// Tests: AUTH con versión incorrecta
// ============================================================
START_TEST (test_auth_wrong_version) {
    setup_buffer();

    // VER=0x02 (incorrecto, debe ser 0x01)
    const uint8_t msg[] = {0x02, 0x04, 't', 'e', 's', 't', 0x04, 'p', 'a', 's', 's'};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    bool error = false;
    enum auth_state st = auth_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(AUTH_ERROR_VER, st);
    ck_assert_int_eq(true, error);
}
END_TEST

// ============================================================
// Tests: AUTH con ULEN = 0 (inválido)
// ============================================================
START_TEST (test_auth_zero_ulen) {
    setup_buffer();

    // VER=0x01, ULEN=0 (inválido)
    const uint8_t msg[] = {0x01, 0x00};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    bool error = false;
    enum auth_state st = auth_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(AUTH_ERROR, st);
    ck_assert_int_eq(true, error);
}
END_TEST

// ============================================================
// Tests: AUTH con PLEN = 0 (inválido)
// ============================================================
START_TEST (test_auth_zero_plen) {
    setup_buffer();

    // VER=0x01, ULEN=4, UNAME="test", PLEN=0 (inválido)
    const uint8_t msg[] = {0x01, 0x04, 't', 'e', 's', 't', 0x00};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    bool error = false;
    enum auth_state st = auth_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(AUTH_ERROR, st);
    ck_assert_int_eq(true, error);
}
END_TEST

// ============================================================
// Tests: AUTH con username y password vacíos (solo si ULEN/PLEN > 0)
// ============================================================
START_TEST (test_auth_single_char) {
    setup_buffer();

    // VER=0x01, ULEN=1, UNAME="a", PLEN=1, PASSWD="b"
    const uint8_t msg[] = {0x01, 0x01, 'a', 0x01, 'b'};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    bool error = false;
    enum auth_state st = auth_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(AUTH_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_str_eq("a", result.username);
    ck_assert_str_eq("b", result.password);
}
END_TEST

// ============================================================
// Tests: AUTH_MARSHALL éxito
// ============================================================
START_TEST (test_auth_marshall_success) {
    setup_buffer();

    int ret = auth_marshall(&test_buff, SOCKS_AUTH_SUCCESS);
    ck_assert_int_eq(0, ret);

    // Verificar: [VER=0x01] [STATUS=0x00]
    ck_assert_uint_eq(true, buffer_can_read(&test_buff));
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
}
END_TEST

// ============================================================
// Tests: AUTH_MARSHALL fallo
// ============================================================
START_TEST (test_auth_marshall_failure) {
    setup_buffer();

    int ret = auth_marshall(&test_buff, SOCKS_AUTH_FAILURE);
    ck_assert_int_eq(0, ret);

    // Verificar: [VER=0x01] [STATUS=0x01]
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
    ck_assert_uint_eq(0x01, buffer_read(&test_buff));
}
END_TEST

// ============================================================
// Tests: AUTH_MARSHALL sin espacio en buffer
// ============================================================
START_TEST (test_auth_marshall_no_buffer) {
    uint8_t tiny[1];
    buffer_init(&test_buff, 1, tiny);

    int ret = auth_marshall(&test_buff, SOCKS_AUTH_SUCCESS);
    ck_assert_int_eq(-1, ret);
}
END_TEST

// ============================================================
// Tests: consumo byte a byte (parcial)
// ============================================================
START_TEST (test_auth_byte_by_byte) {
    struct auth_result result;
    struct auth_parser parser;
    auth_parser_init(&parser, &result);

    // Alimentar byte a byte: user="ab", pass="cd"
    ck_assert_uint_eq(AUTH_ULEN,   auth_parser_feed(&parser, 0x01));
    ck_assert_uint_eq(AUTH_UNAME,  auth_parser_feed(&parser, 0x02));
    ck_assert_uint_eq(AUTH_UNAME,  auth_parser_feed(&parser, 'a'));
    ck_assert_uint_eq(AUTH_PLEN,   auth_parser_feed(&parser, 'b'));
    ck_assert_uint_eq(AUTH_PASSWD, auth_parser_feed(&parser, 0x02));
    ck_assert_uint_eq(AUTH_PASSWD, auth_parser_feed(&parser, 'c'));
    ck_assert_uint_eq(AUTH_DONE,   auth_parser_feed(&parser, 'd'));

    ck_assert_str_eq("ab", result.username);
    ck_assert_str_eq("cd", result.password);
}
END_TEST

// ============================================================
// Suite
// ============================================================
Suite *
auth_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("socks5_auth");

    tc = tcase_create("auth_parser");
    tcase_add_test(tc, test_auth_valid);
    tcase_add_test(tc, test_auth_long_username);
    tcase_add_test(tc, test_auth_wrong_version);
    tcase_add_test(tc, test_auth_zero_ulen);
    tcase_add_test(tc, test_auth_zero_plen);
    tcase_add_test(tc, test_auth_single_char);
    tcase_add_test(tc, test_auth_byte_by_byte);
    suite_add_tcase(s, tc);

    tc = tcase_create("auth_marshall");
    tcase_add_test(tc, test_auth_marshall_success);
    tcase_add_test(tc, test_auth_marshall_failure);
    tcase_add_test(tc, test_auth_marshall_no_buffer);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = auth_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
