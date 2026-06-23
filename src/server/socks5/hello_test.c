/**
 * hello_test.c - tests unitarios para el parser del mensaje HELLO de SOCKS5
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "hello.h"
#include "buffer.h"

// Buffer de respaldo para pruebas
static uint8_t test_buff_data[256];
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

/**
 * Callback del parser: selecciona el método de autenticación.
 * Solo acepta NO AUTHENTICATION REQUIRED (0x00).
 */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = (uint8_t *)p->data;

    if (SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
        *selected = method;
    }
}

// ============================================================
// Tests: HELLO válido sin autenticación
// ============================================================
START_TEST (test_hello_valid_no_auth) {
    setup_buffer();

    // Cliente envía: VER=0x05, NMETHODS=1, METHODS=[0x00]
    const uint8_t msg[] = {0x05, 0x01, 0x00};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct hello_parser parser;
    hello_parser_init(&parser);

    uint8_t selected_method = 0xFF;
    parser.data = &selected_method;
    parser.on_authentication_method = on_hello_method;

    bool error = false;
    enum hello_state st = hello_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(HELLO_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_uint_eq(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED, selected_method);
}
END_TEST

// ============================================================
// Tests: HELLO válido con user/pass
// ============================================================
START_TEST (test_hello_valid_user_pass) {
    setup_buffer();

    // Cliente envía: VER=0x05, NMETHODS=2, METHODS=[0x00, 0x02]
    const uint8_t msg[] = {0x05, 0x02, 0x00, 0x02};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct hello_parser parser;
    hello_parser_init(&parser);

    uint8_t selected_method = 0xFF;
    parser.data = &selected_method;
    parser.on_authentication_method = on_hello_method;

    bool error = false;
    enum hello_state st = hello_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(HELLO_DONE, st);
    ck_assert_int_eq(false, error);
    // Debe seleccionar 0x00 (no auth) porque on_hello_method solo selecciona 0x00
    ck_assert_uint_eq(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED, selected_method);
}
END_TEST

// ============================================================
// Tests: HELLO con versión incorrecta
// ============================================================
START_TEST (test_hello_wrong_version) {
    setup_buffer();

    // Cliente envía: VER=0x04 (incorrecto)
    const uint8_t msg[] = {0x04, 0x01, 0x00};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct hello_parser parser;
    hello_parser_init(&parser);

    bool error = false;
    enum hello_state st = hello_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(HELLO_ERROR_VER, st);
    ck_assert_int_eq(true, error);
}
END_TEST

// ============================================================
// Tests: HELLO con NMETHODS = 0 (inválido)
// ============================================================
START_TEST (test_hello_zero_methods) {
    setup_buffer();

    // Cliente envía: VER=0x05, NMETHODS=0 (inválido)
    const uint8_t msg[] = {0x05, 0x00};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct hello_parser parser;
    hello_parser_init(&parser);

    bool error = false;
    enum hello_state st = hello_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(HELLO_ERROR, st);
    ck_assert_int_eq(true, error);
}
END_TEST

// ============================================================
// Tests: HELLO con múltiples métodos
// ============================================================
START_TEST (test_hello_multiple_methods) {
    setup_buffer();

    // Cliente envía: VER=0x05, NMETHODS=3, METHODS=[0x01, 0x02, 0x00]
    const uint8_t msg[] = {0x05, 0x03, 0x01, 0x02, 0x00};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct hello_parser parser;
    hello_parser_init(&parser);

    uint8_t selected_method = 0xFF;
    parser.data = &selected_method;
    parser.on_authentication_method = on_hello_method;

    bool error = false;
    enum hello_state st = hello_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(HELLO_DONE, st);
    ck_assert_int_eq(false, error);
    ck_assert_uint_eq(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED, selected_method);
}
END_TEST

// ============================================================
// Tests: HELLO sin métodos aceptables
// ============================================================
START_TEST (test_hello_no_acceptable_methods) {
    setup_buffer();

    // Cliente envía: VER=0x05, NMETHODS=1, METHODS=[0x01] (solo GSSAPI)
    const uint8_t msg[] = {0x05, 0x01, 0x01};
    feed_bytes(&test_buff, msg, sizeof(msg));

    struct hello_parser parser;
    hello_parser_init(&parser);

    uint8_t selected_method = 0xFF;
    parser.data = &selected_method;
    parser.on_authentication_method = on_hello_method;

    bool error = false;
    enum hello_state st = hello_consume(&test_buff, &parser, &error);

    ck_assert_uint_eq(HELLO_DONE, st);
    ck_assert_int_eq(false, error);
    // No se seleccionó ningún método aceptable
    ck_assert_uint_eq(SOCKS_HELLO_NO_ACCEPTABLE_METHODS, selected_method);
}
END_TEST

// ============================================================
// Tests: HELLO_MARSHALL
// ============================================================
START_TEST (test_hello_marshall_ok) {
    setup_buffer();

    int ret = hello_marshall(&test_buff, SOCKS_HELLO_NOAUTHENTICATION_REQUIRED);
    ck_assert_int_eq(0, ret);

    // Verificar contenido: [VER=0x05] [METHOD=0x00]
    ck_assert_uint_eq(true, buffer_can_read(&test_buff));
    ck_assert_uint_eq(0x05, buffer_read(&test_buff));
    ck_assert_uint_eq(0x00, buffer_read(&test_buff));
}
END_TEST

START_TEST (test_hello_marshall_no_buffer) {
    // Buffer con capacidad 0
    uint8_t tiny[1];
    buffer_init(&test_buff, 1, tiny);

    int ret = hello_marshall(&test_buff, SOCKS_HELLO_NOAUTHENTICATION_REQUIRED);
    ck_assert_int_eq(-1, ret);
}
END_TEST

// ============================================================
// Tests: consumo byte a byte (parcial)
// ============================================================
START_TEST (test_hello_byte_by_byte) {
    struct hello_parser parser;
    hello_parser_init(&parser);

    uint8_t selected_method = 0xFF;
    parser.data = &selected_method;
    parser.on_authentication_method = on_hello_method;

    // Alimentar byte a byte
    ck_assert_uint_eq(HELLO_NMETHODS, hello_parser_feed(&parser, 0x05));
    ck_assert_uint_eq(HELLO_METHODS,  hello_parser_feed(&parser, 0x01));
    ck_assert_uint_eq(HELLO_DONE,     hello_parser_feed(&parser, 0x00));

    ck_assert_uint_eq(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED, selected_method);
}
END_TEST

// ============================================================
// Suite
// ============================================================
Suite *
hello_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("socks5_hello");

    tc = tcase_create("hello_parser");
    tcase_add_test(tc, test_hello_valid_no_auth);
    tcase_add_test(tc, test_hello_valid_user_pass);
    tcase_add_test(tc, test_hello_wrong_version);
    tcase_add_test(tc, test_hello_zero_methods);
    tcase_add_test(tc, test_hello_multiple_methods);
    tcase_add_test(tc, test_hello_no_acceptable_methods);
    tcase_add_test(tc, test_hello_byte_by_byte);
    suite_add_tcase(s, tc);

    tc = tcase_create("hello_marshall");
    tcase_add_test(tc, test_hello_marshall_ok);
    tcase_add_test(tc, test_hello_marshall_no_buffer);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hello_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
