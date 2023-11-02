/*
 * Copyright 2023 Jakub Jelen <jjelen@redhat.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIBSSH_STATIC 1
#include "libssh/libssh.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssh_key pkey = NULL;
    const char *template = "/tmp/libssh_pubkey_XXXXXX";
    char *filename = strdup(template);
    int fd;
    int rc;
    ssize_t sz;

    ssh_init();

    if (filename == NULL) {
        return -1;
    }
    fd = mkstemp(filename);
    if (fd  == -1) {
        free(filename);
        close(fd);
        return -1;
    }
    sz = write(fd, data, size);
    close(fd);
    if ((size_t)sz != size) {
        unlink(filename);
        free(filename);
        return -1;
    }

    rc = ssh_pki_import_pubkey_file(filename, &pkey);
    if (rc != SSH_OK) {
        unlink(filename);
        free(filename);
        return 1;
    }
    ssh_key_free(pkey);
    unlink(filename);
    free(filename);

    ssh_finalize();

    return 0;
}

