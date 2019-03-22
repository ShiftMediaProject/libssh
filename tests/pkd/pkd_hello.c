/*
 * pkd_hello.c --
 *
 * (c) 2014, 2017-2018 Jon Simons <jon@jonsimons.org>
 */
#include "config.h"

#include <setjmp.h> // for cmocka
#include <stdarg.h> // for cmocka
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for cmocka
#include <cmocka.h>

#include "libssh/priv.h"

#include "pkd_client.h"
#include "pkd_daemon.h"
#include "pkd_keyutil.h"
#include "pkd_util.h"

#define DEFAULT_ITERATIONS 10
static struct pkd_daemon_args pkd_dargs;

#ifdef HAVE_ARGP_H
#include <argp.h>
#define PROGNAME "pkd_hello"
#define ARGP_PROGNAME "libssh " PROGNAME
const char *argp_program_version = ARGP_PROGNAME " 2017-07-12";
const char *argp_program_bug_address = "Jon Simons <jon@jonsimons.org>";

static char doc[] = \
    "\nExample usage:\n\n"
    "    " PROGNAME "\n"
    "        Run all tests with default number of iterations.\n"
    "    " PROGNAME " --list\n"
    "        List available individual test names.\n"
    "    " PROGNAME " -i 1000 -t torture_pkd_rsa_ecdh_sha2_nistp256\n"
    "        Run only the torture_pkd_rsa_ecdh_sha2_nistp256 testcase 1000 times.\n"
    "    " PROGNAME " -i 1000 -m curve25519\n"
    "        Run all tests with the string 'curve25519' 1000 times.\n"
    "    " PROGNAME " -v -v -v -v -e -o\n"
    "        Run all tests with maximum libssh and pkd logging.\n"
;

static struct argp_option options[] = {
    { "stderr", 'e', NULL, 0,
      "Emit pkd stderr messages", 0 },
    { "list", 'l', NULL, 0,
      "List available individual test names", 0 },
    { "iterations", 'i', "number", 0,
      "Run each test for the given number of iterations (default is 10)", 0 },
    { "match", 'm', "testmatch", 0,
      "Run all tests with the given string", 0 },
    { "socket-wrapper-dir", 'w', "<mkdtemp-template>", 0,
      "Run in socket-wrapper mode using the given mkdtemp directory template", 0 },
    { "stdout", 'o', NULL, 0,
      "Emit pkd stdout messages", 0 },
    { "test", 't', "testname", 0,
      "Run tests matching the given testname", 0 },
    { "verbose", 'v', NULL, 0,
      "Increase libssh verbosity (can be used multiple times)", 0 },
    { NULL, 0, NULL, 0,
      NULL, 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    (void) arg;
    (void) state;

    switch(key) {
    case 'e':
        pkd_dargs.opts.log_stderr = 1;
        break;
    case 'l':
        pkd_dargs.opts.list = 1;
        break;
    case 'i':
        pkd_dargs.opts.iterations = atoi(arg);
        break;
    case 'm':
        pkd_dargs.opts.testmatch = arg;
        break;
    case 'o':
        pkd_dargs.opts.log_stdout = 1;
        break;
    case 't':
        pkd_dargs.opts.testname = arg;
        break;
    case 'v':
        pkd_dargs.opts.libssh_log_level += 1;
        break;
    case 'w':
        pkd_dargs.opts.socket_wrapper.mkdtemp_str = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp parser = {
    options,
    parse_opt,
    NULL,
    doc,
    NULL,
    NULL,
    NULL
};
#endif /* HAVE_ARGP_H */

static struct pkd_state *torture_pkd_setup(enum pkd_hostkey_type_e type,
                                           const char *hostkeypath) {
    int rc = 0;

    pkd_dargs.type = type;
    pkd_dargs.hostkeypath = hostkeypath;

    rc = pkd_start(&pkd_dargs);
    assert_int_equal(rc, 0);

    return NULL;
}

static int torture_pkd_teardown(void **state) {
    struct pkd_result result = { .ok = 0 };

    (void) state;

    pkd_stop(&result);
    assert_int_equal(result.ok, 1);

    return 0;
}

/*
 * one setup for each server keytype ------------------------------------
 */

static int torture_pkd_setup_noop(void **state) {
    *state = (void *) torture_pkd_setup(PKD_RSA, NULL /*path*/);

    return 0;
}

static int torture_pkd_setup_rsa(void **state) {
    setup_rsa_key();
    *state = (void *) torture_pkd_setup(PKD_RSA, LIBSSH_RSA_TESTKEY);

    return 0;
}

static int torture_pkd_setup_ed25519(void **state) {
    setup_ed25519_key();
    *state = (void *) torture_pkd_setup(PKD_ED25519, LIBSSH_ED25519_TESTKEY);

    return 0;
}

#ifdef HAVE_DSA
static int torture_pkd_setup_dsa(void **state) {
    setup_dsa_key();
    *state = (void *) torture_pkd_setup(PKD_DSA, LIBSSH_DSA_TESTKEY);

    return 0;
}
#endif

static int torture_pkd_setup_ecdsa_256(void **state) {
    setup_ecdsa_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA, LIBSSH_ECDSA_256_TESTKEY);

    return 0;
}

static int torture_pkd_setup_ecdsa_384(void **state) {
    setup_ecdsa_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA, LIBSSH_ECDSA_384_TESTKEY);

    return 0;
}

static int torture_pkd_setup_ecdsa_521(void **state) {
    setup_ecdsa_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA, LIBSSH_ECDSA_521_TESTKEY);

    return 0;
}

/*
 * Test matrices: f(clientname, testname, ssh-command, setup-function, teardown-function).
 */

#ifdef HAVE_DSA
#define PKDTESTS_DEFAULT(f, client, cmd) \
    /* Default passes by server key type. */ \
    f(client, rsa_default,        cmd,  setup_rsa,        teardown) \
    f(client, dsa_default,        cmd,  setup_dsa,        teardown) \
    f(client, ecdsa_256_default,  cmd,  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_default,  cmd,  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_default,  cmd,  setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_DEFAULT(f, client, cmd) \
    /* Default passes by server key type. */ \
    f(client, rsa_default,        cmd,  setup_rsa,        teardown) \
    f(client, ecdsa_256_default,  cmd,  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_default,  cmd,  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_default,  cmd,  setup_ecdsa_521,  teardown)
#endif

#define PKDTESTS_DEFAULT_OPENSSHONLY(f, client, cmd) \
    /* Default passes by server key type. */ \
    f(client, ed25519_default,    cmd,  setup_ed25519,    teardown)

#ifdef HAVE_DSA
#define PKDTESTS_KEX(f, client, kexcmd) \
    /* Kex algorithms. */ \
    f(client, rsa_curve25519_sha256,                  kexcmd("curve25519-sha256"),             setup_rsa,        teardown) \
    f(client, rsa_curve25519_sha256_libssh_org,       kexcmd("curve25519-sha256@libssh.org"),  setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521"),            setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group14_sha1,        kexcmd("diffie-hellman-group14-sha1"),   setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group1_sha1,         kexcmd("diffie-hellman-group1-sha1"),    setup_rsa,        teardown) \
    f(client, dsa_curve25519_sha256,                  kexcmd("curve25519-sha256"),             setup_dsa,        teardown) \
    f(client, dsa_curve25519_sha256_libssh_org,       kexcmd("curve25519-sha256@libssh.org"),  setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256 "),           setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384 "),           setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521 "),           setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group14_sha1,        kexcmd("diffie-hellman-group14-sha1"),   setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group1_sha1,         kexcmd("diffie-hellman-group1-sha1"),    setup_dsa,        teardown) \
    f(client, ecdsa_256_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_KEX(f, client, kexcmd) \
    /* Kex algorithms. */ \
    f(client, rsa_curve25519_sha256,                  kexcmd("curve25519-sha256"),             setup_rsa,        teardown) \
    f(client, rsa_curve25519_sha256_libssh_org,       kexcmd("curve25519-sha256@libssh.org"),  setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521"),            setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group14_sha1,        kexcmd("diffie-hellman-group14-sha1"),   setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group1_sha1,         kexcmd("diffie-hellman-group1-sha1"),    setup_rsa,        teardown) \
    f(client, ecdsa_256_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_521,  teardown)
#endif


#ifdef HAVE_DSA
#define PKDTESTS_KEX_OPENSSHONLY(f, client, kexcmd) \
    /* Kex algorithms. */ \
    f(client, ed25519_curve25519_sha256,              kexcmd("curve25519-sha256"),             setup_ed25519,    teardown) \
    f(client, ed25519_curve25519_sha256_libssh_org,   kexcmd("curve25519-sha256@libssh.org"),  setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp256,             kexcmd("ecdh-sha2-nistp256"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp384,             kexcmd("ecdh-sha2-nistp384"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp521,             kexcmd("ecdh-sha2-nistp521"),            setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group16_sha512,  kexcmd("diffie-hellman-group16-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group18_sha512,  kexcmd("diffie-hellman-group18-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group14_sha1,    kexcmd("diffie-hellman-group14-sha1"),   setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group1_sha1,     kexcmd("diffie-hellman-group1-sha1"),    setup_ed25519,    teardown)
#else
#define PKDTESTS_KEX_OPENSSHONLY(f, client, kexcmd) \
    /* Kex algorithms. */ \
    f(client, ed25519_curve25519_sha256,              kexcmd("curve25519-sha256"),             setup_ed25519,    teardown) \
    f(client, ed25519_curve25519_sha256_libssh_org,   kexcmd("curve25519-sha256@libssh.org"),  setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp256,             kexcmd("ecdh-sha2-nistp256"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp384,             kexcmd("ecdh-sha2-nistp384"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp521,             kexcmd("ecdh-sha2-nistp521"),            setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group16_sha512,  kexcmd("diffie-hellman-group16-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group18_sha512,  kexcmd("diffie-hellman-group18-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group1_sha1,     kexcmd("diffie-hellman-group1-sha1"),    setup_ed25519,    teardown)
#endif

#ifdef HAVE_DSA
#define PKDTESTS_CIPHER(f, client, ciphercmd) \
    /* Ciphers. */ \
    f(client, rsa_3des_cbc,            ciphercmd("3des-cbc"),      setup_rsa,        teardown) \
    f(client, rsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes128_ctr,          ciphercmd("aes128-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_ctr,          ciphercmd("aes256-ctr"),    setup_rsa,        teardown) \
    f(client, dsa_3des_cbc,            ciphercmd("3des-cbc"),      setup_dsa,        teardown) \
    f(client, dsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_dsa,        teardown) \
    f(client, dsa_aes128_ctr,          ciphercmd("aes128-ctr"),    setup_dsa,        teardown) \
    f(client, dsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_dsa,        teardown) \
    f(client, dsa_aes256_ctr,          ciphercmd("aes256-ctr"),    setup_dsa,        teardown) \
    f(client, ecdsa_256_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_CIPHER(f, client, ciphercmd) \
    /* Ciphers. */ \
    f(client, rsa_3des_cbc,            ciphercmd("3des-cbc"),      setup_rsa,        teardown) \
    f(client, rsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes128_ctr,          ciphercmd("aes128-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_ctr,          ciphercmd("aes256-ctr"),    setup_rsa,        teardown) \
    f(client, ecdsa_256_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_521,  teardown)
#endif

#define CHACHA20 "chacha20-poly1305@openssh.com"

#ifdef HAVE_DSA
#define PKDTESTS_CIPHER_OPENSSHONLY(f, client, ciphercmd) \
    /* Ciphers. */ \
    f(client, rsa_aes192_cbc,          ciphercmd("aes192-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes192_ctr,          ciphercmd("aes192-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_chacha20,            ciphercmd(CHACHA20),        setup_rsa,        teardown) \
    f(client, dsa_aes192_cbc,          ciphercmd("aes192-cbc"),    setup_dsa,        teardown) \
    f(client, dsa_aes192_ctr,          ciphercmd("aes192-ctr"),    setup_dsa,        teardown) \
    f(client, dsa_chacha20,            ciphercmd(CHACHA20),        setup_dsa,        teardown) \
    f(client, ed25519_3des_cbc,        ciphercmd("3des-cbc"),      setup_ed25519,    teardown) \
    f(client, ed25519_aes128_cbc,      ciphercmd("aes128-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes128_ctr,      ciphercmd("aes128-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_cbc,      ciphercmd("aes256-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_ctr,      ciphercmd("aes256-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_cbc,      ciphercmd("aes192-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_ctr,      ciphercmd("aes192-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_chacha20,        ciphercmd(CHACHA20),        setup_ed25519,    teardown) \
    f(client, ecdsa_256_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_CIPHER_OPENSSHONLY(f, client, ciphercmd) \
    /* Ciphers. */ \
    f(client, rsa_aes192_cbc,          ciphercmd("aes192-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes192_ctr,          ciphercmd("aes192-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_chacha20,            ciphercmd(CHACHA20),        setup_rsa,        teardown) \
    f(client, ed25519_3des_cbc,        ciphercmd("3des-cbc"),      setup_ed25519,    teardown) \
    f(client, ed25519_aes128_cbc,      ciphercmd("aes128-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes128_ctr,      ciphercmd("aes128-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_cbc,      ciphercmd("aes256-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_ctr,      ciphercmd("aes256-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_cbc,      ciphercmd("aes192-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_ctr,      ciphercmd("aes192-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_chacha20,        ciphercmd(CHACHA20),        setup_ed25519,    teardown) \
    f(client, ecdsa_256_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_521,  teardown)
#endif

#ifdef HAVE_DSA
#define PKDTESTS_MAC(f, client, maccmd) \
    /* MACs. */ \
    f(client, rsa_hmac_sha1,            maccmd("hmac-sha1"),      setup_rsa,        teardown) \
    f(client, dsa_hmac_sha1,            maccmd("hmac-sha1"),      setup_dsa,        teardown) \
    f(client, ecdsa_256_hmac_sha1,      maccmd("hmac-sha1"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha1,      maccmd("hmac-sha1"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha1,      maccmd("hmac-sha1"),      setup_ecdsa_521,  teardown) \
    f(client, rsa_hmac_sha2_256,        maccmd("hmac-sha2-256"),  setup_rsa,        teardown) \
    f(client, dsa_hmac_sha2_256,        maccmd("hmac-sha2-256"),  setup_dsa,        teardown) \
    f(client, ecdsa_256_hmac_sha2_256,  maccmd("hmac-sha2-256"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha2_256,  maccmd("hmac-sha2-256"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha2_256,  maccmd("hmac-sha2-256"),  setup_ecdsa_521,  teardown)
#define PKDTESTS_MAC_OPENSSHONLY(f, client, maccmd) \
    f(client, ed25519_hmac_sha1,        maccmd("hmac-sha1"),      setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_256,    maccmd("hmac-sha2-256"),  setup_ed25519,    teardown) \
    f(client, rsa_hmac_sha2_512,        maccmd("hmac-sha2-512"),  setup_rsa,        teardown) \
    f(client, dsa_hmac_sha2_512,        maccmd("hmac-sha2-512"),  setup_dsa,        teardown) \
    f(client, ed25519_hmac_sha2_512,    maccmd("hmac-sha2-512"),  setup_ed25519,    teardown) \
    f(client, ecdsa_256_hmac_sha2_512,  maccmd("hmac-sha2-512"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha2_512,  maccmd("hmac-sha2-512"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha2_512,  maccmd("hmac-sha2-512"),  setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_MAC(f, client, maccmd) \
    /* MACs. */ \
    f(client, rsa_hmac_sha1,            maccmd("hmac-sha1"),      setup_rsa,        teardown) \
    f(client, ecdsa_256_hmac_sha1,      maccmd("hmac-sha1"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha1,      maccmd("hmac-sha1"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha1,      maccmd("hmac-sha1"),      setup_ecdsa_521,  teardown) \
    f(client, rsa_hmac_sha2_256,        maccmd("hmac-sha2-256"),  setup_rsa,        teardown) \
    f(client, ecdsa_256_hmac_sha2_256,  maccmd("hmac-sha2-256"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha2_256,  maccmd("hmac-sha2-256"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha2_256,  maccmd("hmac-sha2-256"),  setup_ecdsa_521,  teardown)
#define PKDTESTS_MAC_OPENSSHONLY(f, client, maccmd) \
    f(client, ed25519_hmac_sha1,        maccmd("hmac-sha1"),      setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_256,    maccmd("hmac-sha2-256"),  setup_ed25519,    teardown) \
    f(client, rsa_hmac_sha2_512,        maccmd("hmac-sha2-512"),  setup_rsa,        teardown) \
    f(client, ed25519_hmac_sha2_512,    maccmd("hmac-sha2-512"),  setup_ed25519,    teardown) \
    f(client, ecdsa_256_hmac_sha2_512,  maccmd("hmac-sha2-512"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha2_512,  maccmd("hmac-sha2-512"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha2_512,  maccmd("hmac-sha2-512"),  setup_ecdsa_521,  teardown)
#endif

#define PKDTESTS_HOSTKEY_OPENSSHONLY(f, client, hkcmd) \
    f(client, rsa_sha2_256,     hkcmd("rsa-sha2-256"),               setup_rsa,    teardown) \
    f(client, rsa_sha2_512,     hkcmd("rsa-sha2-512"),               setup_rsa,    teardown) \
    f(client, rsa_sha2_256_512, hkcmd("rsa-sha2-256,rsa-sha2-512"),  setup_rsa,    teardown) \
    f(client, rsa_sha2_512_256, hkcmd("rsa-sha2-512,rsa-sha2-256"),  setup_rsa,    teardown)

static void torture_pkd_client_noop(void **state) {
    struct pkd_state *pstate = (struct pkd_state *) (*state);
    (void) pstate;
    return;
}

static void torture_pkd_runtest(const char *testname,
                                const char *testcmd)
{
    int i, rc;
    char logfile[1024] = { 0 };
    int iterations =
        (pkd_dargs.opts.iterations != 0) ? pkd_dargs.opts.iterations
                                         : DEFAULT_ITERATIONS;

    for (i = 0; i < iterations; i++) {
        rc = system_checked(testcmd);
        assert_int_equal(rc, 0);
    }

    /* Asserts did not trip: cleanup logs. */
    snprintf(&logfile[0], sizeof(logfile), "%s.out", testname);
    unlink(logfile);
    snprintf(&logfile[0], sizeof(logfile), "%s.err", testname);
    unlink(logfile);
}

/*
 * Though each keytest function body is the same, separate functions are
 * defined here to result in distinct output when running the tests.
 */

#define emit_keytest(client, testname, sshcmd, setup, teardown) \
    static void torture_pkd_## client ## _ ## testname(void **state) { \
        const char *tname = "torture_pkd_" #client "_" #testname;      \
        char testcmd[1024] = { 0 };                                    \
        (void) state;                                                  \
        snprintf(&testcmd[0], sizeof(testcmd), sshcmd, tname, tname);  \
        torture_pkd_runtest(tname, testcmd);                           \
    }

/*
 * Actual test functions are emitted here.
 */

#ifdef HAVE_DSA
#define CLIENT_ID_FILE OPENSSH_DSA_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_dsa, OPENSSH_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_dsa, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_dsa, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_dsa, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_MAC_CMD)
#undef CLIENT_ID_FILE
#endif

#define CLIENT_ID_FILE OPENSSH_RSA_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_rsa, OPENSSH_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_rsa, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_rsa, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_rsa, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_MAC_CMD)
PKDTESTS_HOSTKEY_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_HOSTKEY_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA256_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_e256, OPENSSH_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_e256, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_e256, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_e256, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_MAC_CMD)
#undef CLIENT_ID_FILE

/* Could add these passes, too: */
//#define CLIENT_ID_FILE OPENSSH_ECDSA384_TESTKEY
//#define CLIENT_ID_FILE OPENSSH_ECDSA521_TESTKEY

#define CLIENT_ID_FILE OPENSSH_ED25519_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_ed, OPENSSH_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_ed, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_ed, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_ed, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_MAC_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE DROPBEAR_RSA_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, dropbear, DROPBEAR_CMD)
PKDTESTS_CIPHER(emit_keytest, dropbear, DROPBEAR_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, dropbear, DROPBEAR_MAC_CMD)
#undef CLIENT_ID_FILE

/*
 * Define an array of testname strings mapped to their associated
 * test function.  Enables running tests individually by name from
 * the command line.
 */

#define emit_testmap(client, testname, sshcmd, setup, teardown) \
    { "torture_pkd_" #client "_" #testname,                     \
      emit_unit_test(client, testname, sshcmd, setup, teardown) },

#define emit_unit_test(client, testname, sshcmd, setup, teardown) \
    cmocka_unit_test_setup_teardown(torture_pkd_ ## client ## _ ## testname, \
                                    torture_pkd_ ## setup, \
                                    torture_pkd_ ## teardown)

#define emit_unit_test_comma(client, testname, sshcmd, setup, teardown) \
    emit_unit_test(client, testname, sshcmd, setup, teardown),

struct {
    const char *testname;
    const struct CMUnitTest test;
} testmap[] = {
    /* OpenSSH */
#ifdef HAVE_DSA
    PKDTESTS_DEFAULT(emit_testmap, openssh_dsa, OPENSSH_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_dsa, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_dsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_dsa, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_MAC_CMD)
#endif

    PKDTESTS_DEFAULT(emit_testmap, openssh_rsa, OPENSSH_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_rsa, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_rsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_rsa, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_MAC_CMD)
    PKDTESTS_HOSTKEY_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_HOSTKEY_CMD)

    PKDTESTS_DEFAULT(emit_testmap, openssh_e256, OPENSSH_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_e256, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_e256, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_e256, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_MAC_CMD)

    PKDTESTS_DEFAULT(emit_testmap, openssh_ed, OPENSSH_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_ed, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_ed, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_ed, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_MAC_CMD)

    /* Dropbear */
    PKDTESTS_DEFAULT(emit_testmap, dropbear, DROPBEAR_CMD)
    PKDTESTS_CIPHER(emit_testmap, dropbear, DROPBEAR_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, dropbear, DROPBEAR_MAC_CMD)

    /* Noop */
    emit_testmap(client, noop, "", setup_noop, teardown)

    /* NULL tail entry */
    { .testname = NULL,
      .test = { .name = NULL,
                .test_func = NULL,
                .setup_func = NULL,
                .teardown_func = NULL } }
};

static int pkd_run_tests(void) {
    int rc = -1;
    int tindex = 0;

    const struct CMUnitTest openssh_tests[] = {
#ifdef HAVE_DSA
        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_dsa, OPENSSH_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_dsa, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_dsa, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_dsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_dsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_dsa, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_dsa, OPENSSH_MAC_CMD)
#endif

        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_rsa, OPENSSH_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_rsa, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_rsa, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_rsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_rsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_rsa, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_rsa, OPENSSH_MAC_CMD)

        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_e256, OPENSSH_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_e256, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_e256, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_e256, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_e256, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_e256, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_e256, OPENSSH_MAC_CMD)

        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_ed, OPENSSH_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_ed, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_ed, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_ed, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_ed, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_ed, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_ed, OPENSSH_MAC_CMD)
    };

    const struct CMUnitTest dropbear_tests[] = {
        PKDTESTS_DEFAULT(emit_unit_test_comma, dropbear, DROPBEAR_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, dropbear, DROPBEAR_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, dropbear, DROPBEAR_MAC_CMD)
    };

    const struct CMUnitTest noop_tests[] = {
        emit_unit_test(client, noop, "", setup_noop, teardown)
    };

    /* Test list is populated depending on which clients are enabled. */
    struct CMUnitTest all_tests[(sizeof(openssh_tests) / sizeof(openssh_tests[0])) +
                                (sizeof(dropbear_tests) / sizeof(dropbear_tests[0])) +
                                (sizeof(noop_tests) / sizeof(noop_tests[0]))];
    memset(&all_tests[0], 0x0, sizeof(all_tests));

    /* Generate client keys and populate test list for each enabled client. */
    if (is_openssh_client_enabled()) {
        setup_openssh_client_keys();
        memcpy(&all_tests[tindex], &openssh_tests[0], sizeof(openssh_tests));
        tindex += (sizeof(openssh_tests) / sizeof(openssh_tests[0]));
    }

    if (is_dropbear_client_enabled()) {
        setup_dropbear_client_rsa_key();
        memcpy(&all_tests[tindex], &dropbear_tests[0], sizeof(dropbear_tests));
        tindex += (sizeof(dropbear_tests) / sizeof(dropbear_tests[0]));
    }

    memcpy(&all_tests[tindex], &noop_tests[0], sizeof(noop_tests));
    tindex += (sizeof(noop_tests) / sizeof(noop_tests[0]));

    if ((pkd_dargs.opts.testname == NULL) &&
        (pkd_dargs.opts.testmatch == NULL)) {
        rc = _cmocka_run_group_tests("all tests", all_tests, tindex, NULL, NULL);
    } else {
        size_t i = 0;
        size_t num_found = 0;
        const char *testname = pkd_dargs.opts.testname;
        const char *testmatch = pkd_dargs.opts.testmatch;

        struct CMUnitTest matching_tests[sizeof(all_tests)];
        memset(&matching_tests[0], 0x0, sizeof(matching_tests));

        while (testmap[i].testname != NULL) {
            if ((testname != NULL) &&
                (strcmp(testmap[i].testname, testname) == 0)) {
                memcpy(&matching_tests[0],
                       &testmap[i].test,
                       sizeof(struct CMUnitTest));
                num_found += 1;
                break;
            }

            if ((testmatch != NULL) &&
                (strstr(testmap[i].testname, testmatch) != NULL)) {
                memcpy(&matching_tests[num_found],
                       &testmap[i].test,
                       sizeof(struct CMUnitTest));
                num_found += 1;
            }

            i += 1;
        }

        if (num_found > 0) {
            rc = _cmocka_run_group_tests("found", matching_tests, num_found, NULL, NULL);
        } else {
            fprintf(stderr, "Did not find test '%s'\n", testname);
        }
    }

    /* Clean up client keys for each enabled client. */
    if (is_dropbear_client_enabled()) {
        cleanup_dropbear_client_rsa_key();
    }

    if (is_openssh_client_enabled()) {
        cleanup_openssh_client_keys();
    }

    /* Clean up any server keys that were generated. */
    cleanup_rsa_key();
    cleanup_ed25519_key();
#ifdef HAVE_DSA
    cleanup_dsa_key();
#endif
    cleanup_ecdsa_keys();

    return rc;
}

static int pkd_init_socket_wrapper(void) {
    int rc = 0;
    char *mkdtemp_str = NULL;

    if (pkd_dargs.opts.socket_wrapper.mkdtemp_str == NULL) {
        goto out;
    }

    mkdtemp_str = strdup(pkd_dargs.opts.socket_wrapper.mkdtemp_str);
    if (mkdtemp_str == NULL) {
        fprintf(stderr, "pkd_init_socket_wrapper strdup failed\n");
        goto errstrdup;
    }
    pkd_dargs.opts.socket_wrapper.mkdtemp_str = mkdtemp_str;

    if (mkdtemp(mkdtemp_str) == NULL) {
        fprintf(stderr, "pkd_init_socket_wrapper mkdtemp '%s' failed\n", mkdtemp_str);
        goto errmkdtemp;
    }

    if (setenv("SOCKET_WRAPPER_DIR", mkdtemp_str, 1) != 0) {
        fprintf(stderr, "pkd_init_socket_wrapper setenv failed\n");
        goto errsetenv;
    }

    goto out;
errsetenv:
errmkdtemp:
    free(mkdtemp_str);
errstrdup:
    rc = -1;
out:
    return rc;
}

static int pkd_rmfiles(const char *path) {
    char bin[1024] = { 0 };
    snprintf(&bin[0], sizeof(bin), "rm -f %s/*", path);
    return system_checked(bin);
}

static int pkd_cleanup_socket_wrapper(void) {
    int rc = 0;

    if (pkd_dargs.opts.socket_wrapper.mkdtemp_str == NULL) {
        goto out;
    }

    /* clean up socket-wrapper unix domain sockets */
    if (pkd_rmfiles(pkd_dargs.opts.socket_wrapper.mkdtemp_str) != 0) {
        fprintf(stderr, "pkd_cleanup_socket_wrapper pkd_rmfiles '%s' failed\n",
                        pkd_dargs.opts.socket_wrapper.mkdtemp_str);
        goto errrmfiles;
    }

    if (rmdir(pkd_dargs.opts.socket_wrapper.mkdtemp_str) != 0) {
        fprintf(stderr, "pkd_cleanup_socket_wrapper rmdir '%s' failed\n",
                        pkd_dargs.opts.socket_wrapper.mkdtemp_str);
        goto errrmdir;
    }

    free(pkd_dargs.opts.socket_wrapper.mkdtemp_str);

    goto out;
errrmdir:
errrmfiles:
    rc = -1;
out:
    return rc;
}

int main(int argc, char **argv) {
    int i = 0;
    int rc = 0;
    int exit_code = -1;

    unsetenv("SSH_AUTH_SOCK");

    rc = ssh_init();
    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

#ifdef HAVE_ARGP_H
    argp_parse(&parser, argc, argv, 0, 0, NULL);
#else /* HAVE_ARGP_H */
    (void) argc;  (void) argv;
#endif /* HAVE_ARGP_H */

    rc = pkd_init_socket_wrapper();
    if (rc != 0) {
        fprintf(stderr, "pkd_init_socket_wrapper failed: %d\n", rc);
        goto out_finalize;
    }

    if (pkd_dargs.opts.list != 0) {
        while (testmap[i].testname != NULL) {
            printf("%s\n", testmap[i++].testname);
        }
    } else {
        exit_code = pkd_run_tests();
        if (exit_code != 0) {
            fprintf(stderr, "pkd_run_tests failed: %d\n", exit_code);
        }
    }

    rc = pkd_cleanup_socket_wrapper();
    if (rc != 0) {
        fprintf(stderr, "pkd_cleanup_socket_wrapper failed: %d\n", rc);
    }

out_finalize:
    rc = ssh_finalize();
    if (rc != 0) {
        fprintf(stderr, "ssh_finalize: %d\n", rc);
    }
out:
    return exit_code;
}
