#define LIBSSH_STATIC

#include "config.h"

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#define MAX_XFER_BUF_SIZE 16384

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);
    return 0;
}

static int sshd_teardown(void **state)
{
    torture_teardown_sshd_server(state);
    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_sftp_aio_read(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;

    struct {
        char buf[MAX_XFER_BUF_SIZE];
        ssize_t bytes_read;
    } a = {0}, b = {0};

    sftp_file file = NULL;
    sftp_attributes file_attr = NULL;
    int fd;

    size_t chunk_size = MAX_XFER_BUF_SIZE;
    int in_flight_requests = 20;

    sftp_aio aio = NULL;
    struct ssh_list *aio_queue = NULL;

    size_t file_size;
    size_t bytes_requested;
    size_t to_read, total_bytes_read;
    int i, rc;

    aio_queue = ssh_list_new();
    assert_non_null(aio_queue);

    file = sftp_open(t->sftp, SSH_EXECUTABLE, O_RDONLY, 0);
    assert_non_null(file);

    fd = open(SSH_EXECUTABLE, O_RDONLY, 0);
    assert_int_not_equal(fd, -1);

    /* Get the file size */
    file_attr = sftp_stat(t->sftp, SSH_EXECUTABLE);
    assert_non_null(file_attr);
    file_size = file_attr->size;

    bytes_requested = 0;
    for (i = 0;
         i < in_flight_requests && bytes_requested < file_size;
         ++i) {
        to_read = file_size - bytes_requested;
        if (to_read > chunk_size) {
            to_read = chunk_size;
        }

        rc = sftp_aio_begin_read(file, to_read, &aio);
        assert_int_equal(rc, SSH_OK);
        bytes_requested += to_read;

        /* enqueue */
        rc = ssh_list_append(aio_queue, aio);
        assert_int_equal(rc, SSH_OK);
    }

    total_bytes_read = 0;
    while ((aio = ssh_list_pop_head(sftp_aio, aio_queue)) != NULL) {
        a.bytes_read = sftp_aio_wait_read(&aio, a.buf, sizeof(a.buf));
        assert_int_not_equal(a.bytes_read, SSH_ERROR);

        total_bytes_read += (size_t)a.bytes_read;
        if (total_bytes_read != file_size) {
            assert_int_equal((size_t)a.bytes_read, chunk_size);
            /*
             * Failure of this assertion means that a short
             * read is encountered but we have not reached
             * the end of file yet. A short read before reaching
             * the end of file should not occur for disk files
             * according to the SFTP protocol. (In our code the
             * file SSH_EXECUTABLE being read is a disk file)
             */
        }

        /*
         * Check whether the bytes read above are bytes
         * present in the file or some garbage was stored
         * in the buffer supplied to sftp_aio_wait_read().
         */
        b.bytes_read = read(fd, b.buf, a.bytes_read);
        assert_int_equal(a.bytes_read, b.bytes_read);

        rc = memcmp(a.buf, b.buf, (size_t)a.bytes_read);
        assert_int_equal(rc, 0);

        /* Issue more read requests if needed */
        if (bytes_requested == file_size) {
            continue;
        }

        /* else issue more requests */
        to_read = file_size - bytes_requested;
        if (to_read > chunk_size) {
            to_read = chunk_size;
        }

        rc = sftp_aio_begin_read(file, to_read, &aio);
        assert_int_equal(rc, SSH_OK);
        bytes_requested += to_read;

        /* enqueue */
        rc = ssh_list_append(aio_queue, aio);
        assert_int_equal(rc, SSH_OK);
    }

    /*
     * Check whether sftp server responds with an
     * eof for more requests.
     */
    rc = sftp_aio_begin_read(file, chunk_size, &aio);
    assert_int_equal(rc, SSH_OK);

    a.bytes_read = sftp_aio_wait_read(&aio, a.buf, sizeof(a.buf));
    assert_int_equal(a.bytes_read, 0);

    /* Cleanup */
    sftp_attributes_free(file_attr);
    close(fd);
    sftp_close(file);
    ssh_list_free(aio_queue);
}

static void torture_sftp_aio_write(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;

    char file_path[128] = {0};
    sftp_file file = NULL;
    int fd;

    struct {
        char buf[MAX_XFER_BUF_SIZE];
        ssize_t bytes;
    } wr = {0}, rd = {0};

    int in_flight_requests;
    sftp_aio *aio_queue = NULL;
    int rc, i;

    in_flight_requests = 2;
    aio_queue = malloc(sizeof(sftp_aio) * in_flight_requests);
    assert_non_null(aio_queue);

    snprintf(file_path, sizeof(file_path),
             "%s/libssh_sftp_aio_write_test", t->testdir);
    file = sftp_open(t->sftp, file_path, O_CREAT | O_WRONLY, 0777);
    assert_non_null(file);

    fd = open(file_path, O_RDONLY, 0);
    assert_int_not_equal(fd, -1);

    for (i = 0; i < in_flight_requests; ++i) {
        rc = sftp_aio_begin_write(file, wr.buf, sizeof(wr.buf), &aio_queue[i]);
        assert_int_equal(rc, SSH_OK);
    }

    for (i = 0; i < in_flight_requests; ++i) {
        wr.bytes = sftp_aio_wait_write(&aio_queue[i]);
        assert_int_equal(wr.bytes, sizeof(wr.buf));

        /*
         * Check whether the bytes written to the file
         * by SFTP AIO write api were the bytes present
         * in the buffer to write or some garbage was
         * written to the file.
         */
        rd.bytes = read(fd, rd.buf, wr.bytes);
        assert_int_equal(rd.bytes, wr.bytes);

        rc = memcmp(rd.buf, wr.buf, wr.bytes);
        assert_int_equal(rc, 0);
    }

    /* Cleanup */
    close(fd);
    sftp_close(file);
    free(aio_queue);

    rc = unlink(file_path);
    assert_int_equal(rc, 0);
}

static void torture_sftp_aio_negative(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;

    char buf[MAX_XFER_BUF_SIZE] = {0};
    sftp_file file = NULL;
    char file_path[128] = {0};
    sftp_aio aio = NULL;

    size_t chunk_size = MAX_XFER_BUF_SIZE;
    ssize_t bytes_read, bytes_written;
    int rc;

    /* Open a file for reading */
    file = sftp_open(t->sftp, SSH_EXECUTABLE, O_RDONLY, 0);
    assert_non_null(file);

    /* Negative tests for reading start */

    /* Passing NULL as the sftp file handle */
    rc = sftp_aio_begin_read(NULL, chunk_size, &aio);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing 0 as the number of bytes to read */
    rc = sftp_aio_begin_read(file, 0, &aio);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing NULL instead of a pointer to a location to store an aio handle */
    rc = sftp_aio_begin_read(file, chunk_size, NULL);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing NULL instead of a pointer to an aio handle */
    bytes_read = sftp_aio_wait_read(NULL, buf, sizeof(buf));
    assert_int_equal(bytes_read, SSH_ERROR);

    /* Passing NULL as the buffer's address */
    rc = sftp_aio_begin_read(file, chunk_size, &aio);
    assert_int_equal(rc, SSH_OK);

    bytes_read = sftp_aio_wait_read(&aio, NULL, sizeof(buf));
    assert_int_equal(bytes_read, SSH_ERROR);

    /* Passing 0 as the buffer size */
    rc = sftp_aio_begin_read(file, chunk_size, &aio);
    assert_int_equal(rc, SSH_OK);

    bytes_read = sftp_aio_wait_read(&aio, buf, 0);
    assert_int_equal(bytes_read, SSH_ERROR);

    /*
     * Test for the scenario when the number
     * of bytes read exceed the buffer size.
     */
    rc = sftp_seek(file, 0); /* Seek to the start of file */
    assert_int_equal(rc, 0);

    rc = sftp_aio_begin_read(file, 2, &aio);
    assert_int_equal(rc, SSH_OK);

    bytes_read = sftp_aio_wait_read(&aio, buf, 1);
    assert_int_equal(bytes_read, SSH_ERROR);

    sftp_close(file);

    /* Open a file for writing */
    snprintf(file_path, sizeof(file_path),
             "%s/libssh_sftp_aio_write_test", t->testdir);
    file = sftp_open(t->sftp, file_path, O_CREAT | O_WRONLY, 0777);
    assert_non_null(file);

    /* Negative tests for writing start */

    /* Passing NULL as the sftp file handle */
    rc = sftp_aio_begin_write(NULL, buf, MAX_XFER_BUF_SIZE, &aio);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing NULL as the buffer's address */
    rc = sftp_aio_begin_write(file, NULL, MAX_XFER_BUF_SIZE, &aio);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing 0 as the size of buffer */
    rc = sftp_aio_begin_write(file, buf, 0, &aio);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing NULL instead of a pointer to a location to store an aio handle */
    rc = sftp_aio_begin_write(file, buf, MAX_XFER_BUF_SIZE, NULL);
    assert_int_equal(rc, SSH_ERROR);

    /* Passing NULL instead of a pointer to an aio handle */
    bytes_written = sftp_aio_wait_write(NULL);
    assert_int_equal(bytes_written, SSH_ERROR);

    sftp_close(file);
    rc = unlink(file_path);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_aio_read,
                                        session_setup,
                                        session_teardown),

        cmocka_unit_test_setup_teardown(torture_sftp_aio_write,
                                        session_setup,
                                        session_teardown),

        cmocka_unit_test_setup_teardown(torture_sftp_aio_negative,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
