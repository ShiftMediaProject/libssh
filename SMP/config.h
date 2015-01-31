
/************************** HEADER FILES *************************/

/* Define to 1 if you have the <argp.h> header file. */
/* #undef HAVE_ARGP_H */

/* Define to 1 if you have the <pty.h> header file. */
/* #undef HAVE_PTY_H */

/* Define to 1 if you have the <util.h> header file. */
/* #undef HAVE_UTIL_H */

/* Define to 1 if you have the <sys/time.h> header file. */
/* #undef HAVE_SYS_TIME_H */

/* Define to 1 if you have the <termios.h> header file. */
/* #undef HAVE_TERMIOS_H */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <openssl/aes.h> header file. */
/* #undef HAVE_OPENSSL_AES_H */

/* Define to 1 if you have the <wspiapi.h> header file. */
#define HAVE_WSPIAPI_H 1

/* Define to 1 if you have the <openssl/blowfish.h> header file. */
/* #undef HAVE_OPENSSL_BLOWFISH_H */

/* Define to 1 if you have the <openssl/des.h> header file. */
/* #undef HAVE_OPENSSL_DES_H */

/* Define to 1 if you have the <openssl/ecdh.h> header file. */
/* #undef HAVE_OPENSSL_ECDH_H */

/* Define to 1 if you have the <openssl/ec.h> header file. */
/* #undef HAVE_OPENSSL_EC_H */

/* Define to 1 if you have the <openssl/ecdsa.h> header file. */
/* #undef HAVE_OPENSSL_ECDSA_H */

/* Define to 1 if you have the <pthread.h> header file. */
/* #undef HAVE_PTHREAD_H */

/* Define to 1 if you have eliptic curve cryptography in openssl */
/* #undef HAVE_OPENSSL_ECC */

/* Define to 1 if you have eliptic curve cryptography in gcrypt */
#define HAVE_GCRYPT_ECC 1

/* Define to 1 if you have eliptic curve cryptography */
/* #undef HAVE_ECC */

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `snprintf' function. */
/* #undef HAVE_SNPRINTF */

/* Define to 1 if you have the `_snprintf' function. */
#define HAVE__SNPRINTF 1

/* Define to 1 if you have the `_snprintf_s' function. */
#define HAVE__SNPRINTF_S 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the `_vsnprintf' function. */
#define HAVE__VSNPRINTF 1

/* Define to 1 if you have the `_vsnprintf_s' function. */
#define HAVE__VSNPRINTF_S 1

/* Define to 1 if you have the `isblank' function. */
#define HAVE_ISBLANK 1

/* Define to 1 if you have the `strncpy' function. */
#define HAVE_STRNCPY 1

/* Define to 1 if you have the `cfmakeraw' function. */
/* #undef HAVE_CFMAKERAW */

/* Define to 1 if you have the `getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `poll' function. */
/* #undef HAVE_POLL */

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `clock_gettime' function. */
/* #undef HAVE_CLOCK_GETTIME */

/* Define to 1 if you have the `ntohll' function. */
#define HAVE_NTOHLL 1

/* Define to 1 if you have the `htonll' function. */
#define HAVE_HTONLL 1

/* Define to 1 if you have the `strtoull' function. */
#define HAVE_STRTOULL */

/* Define to 1 if you have the `__strtoull' function. */
/* #undef HAVE___STRTOULL */

/* Define to 1 if you have the `_strtoui64' function. */
#define HAVE__STRTOUI64 1

/* Define to 1 if you have the `ntohll' function. */
#define HAVE_NTOHLL 1

/*************************** LIBRARIES ***************************/

/* Define to 1 if you have the `crypto' library (-lcrypto). */
/* #undef HAVE_LIBCRYPTO */

/* Define to 1 if you have the `gcrypt' library (-lgcrypt). */
#define HAVE_LIBGCRYPT 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
/* #undef HAVE_PTHREAD */

/**************************** OPTIONS ****************************/

/* #undef HAVE_GCC_THREAD_LOCAL_STORAGE */
#define HAVE_MSC_THREAD_LOCAL_STORAGE 1

/* #undef HAVE_GCC_VOLATILE_MEMORY_PROTECTION */

/* Define to 1 if you want to enable GSSAPI */
/* #undef WITH_GSSAPI */

/* Define to 1 if you want to enable ZLIB */
#define WITH_ZLIB 1

/* Define to 1 if you want to enable SFTP */
#define WITH_SFTP 1

/* Define to 1 if you want to enable SSH1 */
#define WITH_SSH1 1

/* Define to 1 if you want to enable server support */
#define WITH_SERVER 1

/* Define to 1 if you want to enable debug output for crypto functions */
/* #undef DEBUG_CRYPTO */

/* Define to 1 if you want to enable pcap output support (experimental) */
#define WITH_PCAP 1

/* Define to 1 if you want to enable calltrace debug output */
/* #undef DEBUG_CALLTRACE */

/* Define to 1 if you want to enable NaCl support */
/* #undef WITH_NACL */

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
/* #undef WORDS_BIGENDIAN */
