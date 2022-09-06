/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"
#include "test_server.h"
#include "default_cb.h"

#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <libssh/priv.h>
#include <libssh/sftp.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

/* below are for sftp */
#include <sys/types.h>
#include <sys/statvfs.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>


#define BUF_SIZE 1048576
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)

#define MAX_HANDLE_NUM 10
#define MAX_ENTRIES_NUM_IN_PACKET 50
#define MAX_LONG_NAME_LEN 150

#define SSH_SFTP_CALLBACK(name) \
	static int name (sftp_client_message message)

typedef int (*client_message_callback) (sftp_client_message message);

struct message_handler{
    const char *name;
    const char *extended_name;
    u_int type;

    client_message_callback cb;
};

struct sftp_handle {
    uint8_t type;
    int fd;
    DIR *dirp;
    char *name;
    void *session_id;
};

enum handle_type {
    NULL_HANDLE,
    DIR_HANDLE,
    FILE_HANDLE
};

SSH_SFTP_CALLBACK(process_unsupposed);
SSH_SFTP_CALLBACK(process_open);
SSH_SFTP_CALLBACK(process_read);
SSH_SFTP_CALLBACK(process_write);
SSH_SFTP_CALLBACK(process_close);
SSH_SFTP_CALLBACK(process_opendir);
SSH_SFTP_CALLBACK(process_readdir);
SSH_SFTP_CALLBACK(process_rmdir);
SSH_SFTP_CALLBACK(process_mkdir);
SSH_SFTP_CALLBACK(process_lstat);
SSH_SFTP_CALLBACK(process_readlink);
SSH_SFTP_CALLBACK(process_symlink);
SSH_SFTP_CALLBACK(process_remove);
SSH_SFTP_CALLBACK(process_extended_statvfs);

const struct message_handler message_handlers[] = {
    { "open", NULL, SSH_FXP_OPEN, process_open},
    { "close", NULL, SSH_FXP_CLOSE, process_close},
    { "read", NULL, SSH_FXP_READ, process_read},
    { "write", NULL, SSH_FXP_WRITE, process_write},
    { "lstat", NULL, SSH_FXP_LSTAT, process_lstat},
    { "fstat", NULL, SSH_FXP_FSTAT, process_unsupposed},
    { "setstat", NULL, SSH_FXP_SETSTAT, process_unsupposed},
    { "fsetstat", NULL, SSH_FXP_FSETSTAT, process_unsupposed},
    { "opendir", NULL, SSH_FXP_OPENDIR, process_opendir},
    { "readdir", NULL, SSH_FXP_READDIR, process_readdir},
    { "remove", NULL, SSH_FXP_REMOVE, process_remove},
    { "mkdir", NULL, SSH_FXP_MKDIR, process_mkdir},
    { "rmdir", NULL, SSH_FXP_RMDIR, process_rmdir},
    { "realpath", NULL, SSH_FXP_REALPATH, process_unsupposed},
    { "stat", NULL, SSH_FXP_STAT, process_unsupposed},
    { "rename", NULL, SSH_FXP_RENAME, process_unsupposed},
    { "readlink", NULL, SSH_FXP_READLINK, process_readlink},
    { "symlink", NULL, SSH_FXP_SYMLINK, process_symlink},
    { "init", NULL, SSH_FXP_INIT, sftp_process_init_packet},
    { NULL, NULL, 0, NULL}
};

const struct message_handler extended_handlers[] = {
    /* here are some extended type handlers */
    { "statvfs", "statvfs@openssh.com", 0, process_extended_statvfs},
    { NULL, NULL, 0, NULL}
};

struct sftp_handle s_handle_table[MAX_HANDLE_NUM];

void init_handle_table(int handle_num) {
    int obj_size = sizeof(struct sftp_handle);
    memset(s_handle_table, 0, obj_size*handle_num);
}

static void reinit_single_handle(struct sftp_handle* handle) {
    handle->type = NULL_HANDLE;
    handle->session_id = NULL;
    handle->dirp = NULL;
    handle->name = NULL;
    handle->fd = -1;
}

static int handle_is_ok(int i, int type) {
	return i >= 0 && (u_int)i < MAX_HANDLE_NUM && s_handle_table[i].type == type;
}

static int handle_close(int handle_ind) {
    int ret = SSH_ERROR;

    if (handle_is_ok(handle_ind, FILE_HANDLE)) {
        close(s_handle_table[handle_ind].fd);
        ret = SSH_OK;
    } else if (handle_is_ok(handle_ind, DIR_HANDLE)) {
        closedir((DIR *)s_handle_table[handle_ind].dirp);
        ret = SSH_OK;
    } else if (handle_is_ok(handle_ind, NULL_HANDLE)) {
        ret = SSH_OK;
    }

    if (s_handle_table[handle_ind].name != NULL) {
        free(s_handle_table[handle_ind].name);
        s_handle_table[handle_ind].name = NULL;
    }

    return ret;
}

static int handle_close_by_pointer(struct sftp_handle* handle) {
    if(handle->type == NULL_HANDLE)
        return -1;

    if(handle->fd > 0)
        close(handle->fd);

    if(handle->dirp!=NULL)
        closedir(handle->dirp);

    if(handle->name!=NULL){
        free(handle->name);
        handle->name = NULL;
    }

    return 0;
}

static void free_handles(int handle_num) {
 
    for(int i = 0; i < handle_num; i++) {
        handle_close(i);
        //reinit this handle
        reinit_single_handle(&s_handle_table[i]);
    }
    return;
}

static int add_handle(int type, void *dirp, int fd, const char *name, void *session_id) {
    int ret = SSH_ERROR;
    if(dirp == NULL && fd < 0){
        return ret;
    }

    for(int i = 0; i<MAX_HANDLE_NUM; i++) {
        if(s_handle_table[i].type == NULL_HANDLE){
            s_handle_table[i].type = type;
            s_handle_table[i].session_id = session_id;
            s_handle_table[i].fd = fd;
            s_handle_table[i].dirp = dirp;
            s_handle_table[i].name = malloc((strlen(name) + 1) * sizeof(char));
            strcpy(s_handle_table[i].name, name);

            ret = i;
            break;
        }
    }
    
    if(ret==SSH_ERROR) 
        printf("no other space for new handle\n");

    return ret;
}

static char* get_handle_name(struct sftp_handle* handle) {
    char *ret = NULL;

    if(handle!=NULL&&handle->name!=NULL)
        ret = handle->name;
    
    return ret;
}

static const char* ssh_str_error(int u_errno) {
    switch (u_errno)
    {
        case SSH_FX_NO_SUCH_FILE:
            return "No such file";
        case SSH_FX_PERMISSION_DENIED:
            return "Permission denied";
        case SSH_FX_BAD_MESSAGE:    
            return "Bad message";
        case SSH_FX_OP_UNSUPPORTED:
            return "Operation not supported";
        default:
            return "Operation failed";
    }
    return "Operation failed";
}

static int unix_errno_to_ssh_stat(int u_errno) {
    int ret = SSH_OK;
    switch (u_errno)
    {
        case 0:
            break;
        case ENOENT:
        case ENOTDIR:
        case EBADF:
        case ELOOP:
        {
            ret = SSH_FX_NO_SUCH_FILE;
            break;
        }
        case EPERM:
        case EACCES:
        case EFAULT:
        {
            ret = SSH_FX_PERMISSION_DENIED;
            break;
        }
        case ENAMETOOLONG:
        case EINVAL:
        {
            ret = SSH_FX_BAD_MESSAGE;
            break;
        }
        case ENOSYS:
        {
            ret = SSH_FX_OP_UNSUPPORTED;
            break;
        }
        default:
        {
            ret = SSH_FX_FAILURE;
            break;
        }
    }

    return ret;
}

static void stat_to_filexfer_attrib(const struct stat* z_st, struct sftp_attributes_struct* z_attr)
{
    z_attr->flags = 0;
    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_SIZE;
    z_attr->size = z_st->st_size;

    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_UIDGID;
    z_attr->uid = z_st->st_uid;
    z_attr->gid = z_st->st_gid;

    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS;
    z_attr->permissions = z_st->st_mode;

    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_ACMODTIME;
    z_attr->atime = z_st->st_atime;
    z_attr->mtime = z_st->st_mtime;
}

static void clear_filexfer_attrib(struct sftp_attributes_struct* z_attr)
{
    z_attr->flags = 0;
    z_attr->size = 0;
    z_attr->uid = 0;
    z_attr->gid = 0;
    z_attr->permissions = 0;
    z_attr->atime = 0;
    z_attr->mtime = 0;
}

static int readdir_long_name(char* z_file_name, struct stat* z_st, char* z_long_name)
{
    char tmpbuf[MAX_LONG_NAME_LEN];
    char time[50];
    char* ptr = z_long_name;
    int mode = z_st->st_mode;

    *ptr = '\0';

    switch(mode & S_IFMT)
    {
        case S_IFDIR:
        {
            *ptr++ = 'd';
            break;
        }
        default:
        {
            *ptr++ = '-';
            break;
        }
    }

    /* user */
    if(mode & 0400)
        *ptr++ = 'r';
    else
        *ptr++ ='-';

    if(mode & 0200)
        *ptr++ = 'w';
    else
        *ptr++ = '-';

    if(mode & 0100) {
        if(mode & S_ISUID)
            *ptr++ = 's';
        else
            *ptr++ = 'x';
    } else
        *ptr++ = '-';

    /* group */
    if(mode & 040)
        *ptr++ = 'r';
    else
        *ptr++ = '-';
    if(mode & 020)
        *ptr++ = 'w';
    else
        *ptr++ ='-';
    if(mode & 010)
        *ptr++ = 'x';
    else
        *ptr++ = '-';

    /* other */
    if(mode & 04)
        *ptr++ = 'r';
    else
        *ptr++ = '-';
    if(mode & 02)
        *ptr++ = 'w';
    else
        *ptr++ = '-';
    if(mode & 01)
        *ptr++ = 'x';
    else
        *ptr++ = '-';
    
    *ptr++ = ' ';
    *ptr = '\0';

    snprintf(tmpbuf, sizeof(tmpbuf),"%3d %d %d %d", (int)z_st->st_nlink,
             (int)z_st->st_uid, (int)z_st->st_gid, (int)z_st->st_size);
    strcat(z_long_name, tmpbuf);

    ctime_r(&z_st->st_mtime, time);
    if((ptr = strchr(time,'\n')))
    {
        *ptr = '\0';
    }
    snprintf(tmpbuf,sizeof(tmpbuf)," %s %s", time + 4, z_file_name);
    strcat(z_long_name, tmpbuf);

    return SSH_OK;
}

static int process_open(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *filename = sftp_client_message_get_filename(client_msg);
    uint32_t msg_flag = sftp_client_message_get_flags(client_msg);
    int file_flag;
    int fd = -1;
    int handle_ind = -1;
    int status;

    if (( (msg_flag&(uint32_t)SSH_FXF_READ) == SSH_FXF_READ) && 
       ( (msg_flag&(uint32_t)SSH_FXF_WRITE) == SSH_FXF_WRITE)) {
        file_flag = O_RDWR; //file must exist
        if ((msg_flag & (uint32_t)SSH_FXF_CREAT) == SSH_FXF_CREAT)
            file_flag |= O_CREAT;
    } else if ( (msg_flag&(uint32_t)SSH_FXF_WRITE) == SSH_FXF_WRITE ){
        file_flag = O_WRONLY;
        if ( (msg_flag&(uint32_t)SSH_FXF_APPEND) == SSH_FXF_APPEND )
            file_flag |= O_APPEND;
        if ( (msg_flag&(uint32_t)SSH_FXF_CREAT) == SSH_FXF_CREAT )
            file_flag |= O_CREAT;
    } else if ( (msg_flag&(uint32_t)SSH_FXF_READ) == SSH_FXF_READ ){
        file_flag = O_RDONLY;
    }

    fd = open(filename, file_flag, 0600);
    if(fd == -1){
        status = unix_errno_to_ssh_stat(errno);
        printf("error open file with error: %d\n", errno);
        sftp_reply_status(client_msg, status, "Write error");
        ret = SSH_ERROR;
        return ret;
    }

    handle_ind = add_handle(FILE_HANDLE, NULL, fd, filename, client_msg->sftp);
    if(handle_ind >= 0){
        void *handle_ptr = &s_handle_table[handle_ind];
        ssh_string handle_s = sftp_handle_alloc(client_msg->sftp, handle_ptr);
        sftp_reply_handle(client_msg, handle_s);
        ssh_string_free(handle_s);
        ret = SSH_OK;
    }else {
        close(fd);
        printf("opening file failed");
        sftp_reply_status(client_msg, SSH_FX_FAILURE, "No handle available");
    }
    
    return ret;
}

static int process_read(sftp_client_message client_msg) {
    int ret = SSH_OK;
    struct sftp_handle *client_handle = (struct sftp_handle*)sftp_handle(client_msg->sftp, client_msg->handle);
    uint32_t readn;
    int fd;
    char *buffer;
    int rv;

    if (client_handle == NULL || client_handle->session_id != client_msg->sftp) {
        printf("get wrong handle from msg\n");
        sftp_reply_status(client_msg, SSH_FX_FAILURE, NULL);
        return SSH_ERROR;
    }

    fd = client_handle->fd;

    if (fd < 0) {
        sftp_reply_status(client_msg, SSH_FX_INVALID_HANDLE, NULL);
        printf("error reading file fd: %d\n", fd);
        ret = SSH_ERROR;
        return ret;
    }
    rv = lseek(fd, client_msg->offset, SEEK_SET);
    if (rv == -1) {
        sftp_reply_status(client_msg, SSH_FX_FAILURE, NULL);
        printf("error seeking file fd: %d at offset: %ld\n", fd, client_msg->offset);
        ret = SSH_ERROR;
        return ret;
    }

    buffer = malloc((client_msg->len)*sizeof(char));
    readn = read(fd, buffer, client_msg->len);

    if(readn > 0){
        sftp_reply_data(client_msg, buffer, readn);
    }else if(readn == 0) {
        sftp_reply_status(client_msg, SSH_FX_EOF, "EOF encountered");
    }else {
        sftp_reply_status(client_msg, SSH_FX_FAILURE, NULL);
        printf("read file error!\n");
    }
    return ret;
}

static int process_write(sftp_client_message client_msg) {
    int ret = SSH_OK;
    struct sftp_handle *client_handle = (struct sftp_handle*)sftp_handle(client_msg->sftp, client_msg->handle);
    uint32_t writen;
    int fd;
    const char *msg_data;
    uint32_t len;
    int rv;

    if (client_handle == NULL || client_handle->session_id != client_msg->sftp) {
        printf("get wrong handle from msg\n");
        sftp_reply_status(client_msg, SSH_FX_FAILURE, NULL);
        return SSH_ERROR;
    }

    fd = client_handle->fd;

    if (fd < 0) {
        sftp_reply_status(client_msg, SSH_FX_INVALID_HANDLE, NULL);
        printf("write file fd error!\n");
        ret = SSH_ERROR;
        return ret;
    }

    msg_data = ssh_string_get_char(client_msg->data);
    len = ssh_string_len(client_msg->data);

    rv = lseek(fd, client_msg->offset, SEEK_SET);
    if (rv == -1) {
        sftp_reply_status(client_msg, SSH_FX_FAILURE, NULL);
        printf("error seeking file at offset: %ld\n", client_msg->offset);
    }
    writen = write(fd, msg_data, len);
    if(writen == len) {
        sftp_reply_status(client_msg, SSH_FX_OK, NULL);
    }else {
        sftp_reply_status(client_msg, SSH_FX_FAILURE, "Write error");
    }

    return ret;
}

static int process_close(sftp_client_message client_msg) {
    int ret = SSH_OK;
    struct sftp_handle *client_handle = (struct sftp_handle*)sftp_handle(client_msg->sftp, client_msg->handle);

    if (client_handle == NULL) {
        printf("get wrong handle from msg\n");
        return SSH_ERROR;
    }

    ret = handle_close_by_pointer(client_handle);
    if (ret == SSH_OK) {
        reinit_single_handle(client_handle);
        sftp_reply_status(client_msg, SSH_FX_OK, NULL);
    } else {
        printf("closing file failed\n");
        sftp_reply_status(client_msg, SSH_FX_BAD_MESSAGE, "Invalid handle");
    }

    return ret;
}

static int process_opendir(sftp_client_message client_msg) {
    int ret = SSH_OK;
    DIR *dir = NULL;
    const char *dir_name = sftp_client_message_get_filename(client_msg);
    int handle_ind = -1;

    dir = opendir(dir_name);
    if (dir == NULL) {
        sftp_reply_status(client_msg, SSH_FX_NO_SUCH_FILE, "No such directory");
        return SSH_ERROR;
    }

    handle_ind = add_handle(DIR_HANDLE, dir, -1, dir_name, client_msg->sftp);
    if (handle_ind >= 0) {
        ssh_string handle_s = sftp_handle_alloc(client_msg->sftp, &s_handle_table[handle_ind]);
        sftp_reply_handle(client_msg, handle_s);
        ssh_string_free(handle_s);
        ret = SSH_OK;
    } else {
        closedir(dir);
        sftp_reply_status(client_msg, SSH_FX_FAILURE, "No handle available");
    }
    
    return ret;
}

static int process_readdir(sftp_client_message client_msg) {
    int ret = SSH_OK;
    struct sftp_handle *client_handle = (struct sftp_handle*)sftp_handle(client_msg->sftp, client_msg->handle);
    int entries = 0;
    struct dirent *dentry;
    DIR *dir = NULL;

    char long_path[PATH_MAX];
    int path_length;
    char *handle_name;

    if (client_handle == NULL || client_handle->session_id != client_msg->sftp) {
        printf("get wrong handle from msg\n");
        sftp_reply_status(client_msg, SSH_FX_FAILURE, NULL);
        return SSH_ERROR;
    }

    dir = client_handle->dirp;
    if (dir == NULL) {
        sftp_reply_status(client_msg, SSH_FX_INVALID_HANDLE, NULL);
        printf("read dir handle error!\n");
        ret = SSH_ERROR;
        return ret;
    }

    ret = SSH_OK;
    handle_name = get_handle_name(client_handle);
    if (handle_name == NULL) {
        sftp_reply_status(client_msg, SSH_FX_INVALID_HANDLE, NULL);
        return SSH_ERROR;
    }
    strcpy(long_path, handle_name);
    strcat(long_path, "/");
    path_length = (int)strlen(long_path);

    for(int i=0; i < MAX_ENTRIES_NUM_IN_PACKET; i++) {
        dentry = readdir(dir);

        if (dentry!=NULL) {
            struct sftp_attributes_struct attr;
            struct stat st;
            char long_name[MAX_LONG_NAME_LEN];

            strcpy(&long_path[path_length], dentry->d_name);

            if(lstat(long_path, &st) == 0) {
                stat_to_filexfer_attrib(&st, &attr);
            }
            else {
                clear_filexfer_attrib(&attr);
            }

            if(readdir_long_name(dentry->d_name, &st, long_name) == 0){
                sftp_reply_names_add(client_msg, dentry->d_name, long_name, &attr);
            } else {
                printf("readdir long name error\n");
            }
            
            entries++;
        } else {
            break;
        }
    }

    if (entries > 0) {
        ret = sftp_reply_names(client_msg);
    } else {
        sftp_reply_status(client_msg, SSH_FX_EOF, NULL);
    }

    return ret;
}

static int process_mkdir(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *filename = sftp_client_message_get_filename(client_msg);
    uint32_t msg_flags = client_msg->flags;
    uint32_t permission = client_msg->attr->permissions;
    uint32_t mode = (msg_flags & (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS) ? permission & (uint32_t)07777 : 0777;
    int status = SSH_FX_OK;
    int rv;

    if (filename==NULL) {
        sftp_reply_status(client_msg, SSH_FX_NO_SUCH_FILE, "File name error");
        return SSH_ERROR;
    }

    rv = mkdir(filename, mode);
    if (rv < 0) {
        status = unix_errno_to_ssh_stat(errno);
        ret = SSH_ERROR;
    }

    sftp_reply_status(client_msg, status, NULL);
    
    return ret;
}

static int process_rmdir(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *filename = sftp_client_message_get_filename(client_msg);
    int status = SSH_FX_OK;
    int rv;

    if (filename==NULL) {
        sftp_reply_status(client_msg, SSH_FX_NO_SUCH_FILE, "File name error");
        return SSH_ERROR;
    }

    rv = rmdir(filename);
    if (rv < 0) {
        status = unix_errno_to_ssh_stat(errno);
        ret = SSH_ERROR;
    }

    sftp_reply_status(client_msg, status, NULL);
    
    return ret;
}

static int process_lstat(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *filename = sftp_client_message_get_filename(client_msg);
    struct sftp_attributes_struct attr;
    struct stat st;
    int status = SSH_FX_OK;
    int rv;

    if (filename==NULL) {
        sftp_reply_status(client_msg, SSH_FX_NO_SUCH_FILE, "File name error");
        return SSH_ERROR;
    }

    rv = lstat(filename, &st);
    if (rv < 0) {
        status = unix_errno_to_ssh_stat(errno);
        sftp_reply_status(client_msg, status, NULL);
        ret = SSH_ERROR;
    } else {
        stat_to_filexfer_attrib(&st, &attr);
        sftp_reply_attr(client_msg, &attr);
    }
      
    return ret;
}

static int process_readlink(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *filename = sftp_client_message_get_filename(client_msg);
    char buf[PATH_MAX];
    int len = -1;
    const char *err_msg;
    int status = SSH_FX_OK;

    if (filename==NULL) {
        sftp_reply_status(client_msg, SSH_FX_NO_SUCH_FILE, "File name error");
        return SSH_ERROR;
    }

    len = readlink(filename, buf, sizeof(buf) - 1);
    if (len < 0) {
        printf("read link error with reason: %d\n", errno);
        status = unix_errno_to_ssh_stat(errno);
        err_msg = ssh_str_error(status);
        sftp_reply_status(client_msg, status, err_msg);
        ret = SSH_ERROR;
    } else {
        buf[len] = '\0';
        sftp_reply_name(client_msg, buf, NULL);
    }

    return ret;
}

static int process_symlink(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *destpath = sftp_client_message_get_filename(client_msg);
    const char *srcpath = ssh_string_get_char(client_msg->data);
    int status = SSH_FX_OK;
    int rv;
    // printf("try to create link with src: %s and dest: %s \n", srcpath, destpath);
    
    if (srcpath == NULL || destpath == NULL) {
        sftp_reply_status(client_msg, SSH_FX_NO_SUCH_FILE, "File name error");
        return SSH_ERROR;
    }

    rv = symlink(srcpath, destpath);
    if (rv < 0) {
        status = unix_errno_to_ssh_stat(errno);
        printf("error symlink with error: %d\n", errno);
        sftp_reply_status(client_msg, status, "Write error");
        ret = SSH_ERROR;
    } else {
        sftp_reply_status(client_msg, SSH_FX_OK, "write success");
    }

    return ret;
}

static int process_remove(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *filename = sftp_client_message_get_filename(client_msg);
    int rv;
    int status = SSH_FX_OK;

    rv = unlink(filename);
    if (rv < 0) {
        printf("unlink error with reason: %d\n", errno);
        status = unix_errno_to_ssh_stat(errno);
        ret = SSH_ERROR;
    }

    sftp_reply_status(client_msg, status, NULL);
       
    return ret;
}

static int process_unsupposed(sftp_client_message client_msg) {
    int ret = SSH_OK;
    sftp_reply_status(client_msg, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
    printf("Message type %d not implemented\n", sftp_client_message_get_type(client_msg));
    return ret;
}

static int process_extended_statvfs(sftp_client_message client_msg) {
    int ret = SSH_OK;
    const char *path = sftp_client_message_get_filename(client_msg);
    struct statvfs st;
    int status;
    int rv;

    rv = statvfs(path, &st);
    if (rv == 0) {
        sftp_statvfs_t sftp_statvfs;
        u_int64_t flag;

        sftp_statvfs = calloc(1, sizeof(struct sftp_statvfs_struct));
        if (sftp_statvfs == NULL) {
            goto error;
        }
        
        flag = (st.f_flag & ST_RDONLY) ? SSH_FXE_STATVFS_ST_RDONLY : 0;
        flag |= (st.f_flag & ST_NOSUID) ? SSH_FXE_STATVFS_ST_NOSUID : 0;

        sftp_statvfs->f_bsize = st.f_bsize;
        sftp_statvfs->f_frsize = st.f_frsize;
        sftp_statvfs->f_blocks = st.f_blocks;
        sftp_statvfs->f_bfree = st.f_bfree;
        sftp_statvfs->f_bavail = st.f_bavail;
        sftp_statvfs->f_files = st.f_files;
        sftp_statvfs->f_ffree = st.f_ffree;
        sftp_statvfs->f_favail = st.f_favail;
        sftp_statvfs->f_fsid = st.f_fsid;
        sftp_statvfs->f_flag = flag;
        sftp_statvfs->f_namemax = st.f_namemax;
        
        if(sftp_reply_statvfs(client_msg, sftp_statvfs) == 0)
            return ret;
    }

error:
    status = unix_errno_to_ssh_stat(errno);
    ret = SSH_ERROR;
    sftp_reply_status(client_msg, status, NULL);

    printf("statvfs send failed!\n");
    return ret;
}

static int process_extended(sftp_client_message sftp_msg) {
    int status = SSH_ERROR;

    const char *subtype = sftp_msg->submessage;
    client_message_callback handler = NULL;
    for(int i=0;extended_handlers[i].cb!=NULL;i++){
        if (strcmp(subtype, extended_handlers[i].extended_name) == 0) {
            handler = extended_handlers[i].cb;
            break;
        }
    }
    if (handler!=NULL) {
        status = handler(sftp_msg);
        return status;
    }

    sftp_reply_status(sftp_msg, SSH_FX_OP_UNSUPPORTED, "Extended Operation not supported");
    printf("Extended Message type %s not implemented\n", subtype);
    return SSH_OK;

    return status;
}

static int dispatch_sftp_request(sftp_client_message sftp_msg) {
    int status = SSH_ERROR;
    client_message_callback handler = NULL;
    u_int sft_msg_type = sftp_client_message_get_type(sftp_msg);

    for(int i=0;message_handlers[i].cb!=NULL;i++){
        if (sft_msg_type == message_handlers[i].type) {
            handler = message_handlers[i].cb;
            break;
        }
    }
    if (handler!=NULL)
        status = handler(sftp_msg);
    else
        goto not_implemented;
    
    return status;

not_implemented:
    sftp_reply_status(sftp_msg, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
    printf("Message type %d not implemented\n", sft_msg_type);
    return SSH_OK;
}

static int process_client_message(sftp_client_message client_msg) {
    int status = SSH_OK;
    if (client_msg == NULL) {
        return SSH_ERROR;
    }

    switch(client_msg->type) {
        case SSH_FXP_EXTENDED:
            status = process_extended(client_msg);
            break;
        default:
            status = dispatch_sftp_request(client_msg);
    }

    // status = dispatch_sftp_request(client_msg);
    if (status!=SSH_OK)
        printf("error occur in process client message!\n");

    return status;
}

/* TODO implement proper pam authentication cb */
static int sftp_auth_password_cb(UNUSED_PARAM(ssh_session session),
                     const char *user,
                     const char *password,
                     void *userdata)
{
    bool known_user = false;
    bool valid_password = false;

    struct session_data_st *sdata;

    sdata = (struct session_data_st *)userdata;

    if (sdata == NULL) {
        fprintf(stderr, "Error: NULL userdata\n");
        goto null_userdata;
    }

    if (sdata->username == NULL) {
        fprintf(stderr, "Error: expected username not set\n");
        goto denied;
    }

    if (sdata->password == NULL) {
        fprintf(stderr, "Error: expected password not set\n");
        goto denied;
    }

    printf("Password authentication of user %s\n", user);

    known_user = !(strcmp(user, sdata->username));
    valid_password = !(strcmp(password, sdata->password));

    if (known_user && valid_password) {
        sdata->authenticated = 1;
        sdata->auth_attempts = 0;
        printf("Authenticated\n");
        return SSH_AUTH_SUCCESS;
    }

denied:
    sdata->auth_attempts++;
null_userdata:
    return SSH_AUTH_DENIED;
}


static int sftp_channel_data_cb(UNUSED_PARAM(ssh_session session),
                    UNUSED_PARAM(ssh_channel channel),
                    void *data,
                    uint32_t len,
                    UNUSED_PARAM(int is_stderr),
                    void *userdata)
{
    struct channel_data_st *cdata = (struct channel_data_st *) userdata;
    sftp_session sftp = cdata->sftp;
    sftp_client_message msg;
    int decode_len;
    int rc;

    decode_len = sftp_decode_channel_data_to_packet(sftp, data);
    if(decode_len == -1)
        return -1;

    msg = sftp_get_client_message_from_packet(cdata->sftp);
    rc = process_client_message(msg);
    sftp_client_message_free(msg);
    if(rc != SSH_OK)
        printf("process sftp failed!\n");
    
    return decode_len;
}

static int sftp_channel_subsystem_request_cb(ssh_session session,
                                 ssh_channel channel,
                                 const char *subsystem,
                                 void *userdata)
{
    if (strcmp(subsystem, "sftp") == 0) {
        struct channel_data_st* cdata = (struct channel_data_st*) userdata;

        /* initialize sftp session and file handler */
        cdata->sftp = sftp_server_new(session, channel);
        init_handle_table(MAX_HANDLE_NUM);

        return SSH_OK;
    }
    return SSH_ERROR;
}

static int sftp_channel_write_wontblock_cb(UNUSED_PARAM(ssh_session session),
                               UNUSED_PARAM(ssh_channel channel),
                               UNUSED_PARAM(size_t bytes),
                               UNUSED_PARAM(void *userdata))
{
    /* TODO */

    return 0;
}

static ssh_channel sftp_channel_new_session_cb(ssh_session session, void *userdata)
{
    struct session_data_st *sdata = NULL;
    ssh_channel chan = NULL;

    sdata = (struct session_data_st *)userdata;

    if (sdata == NULL) {
        fprintf(stderr, "NULL userdata");
        goto end;
    }

    chan = ssh_channel_new(session);
    if (chan == NULL) {
        fprintf(stderr, "Error creating channel: %s\n",
                ssh_get_error(session));
        goto end;
    }

    sdata->channel = chan;

end:
    return chan;
}

#ifdef WITH_PCAP
static void set_pcap(struct session_data_st *sdata,
                     ssh_session session,
                     char *pcap_file)
{
    int rc = 0;

    if (sdata == NULL) {
        return;
    }

    if (pcap_file == NULL) {
        return;
    }

    sdata->pcap = ssh_pcap_file_new();
    if (sdata->pcap == NULL) {
        return;
    }

    rc = ssh_pcap_file_open(sdata->pcap, pcap_file);
    if (rc == SSH_ERROR) {
        fprintf(stderr, "Error opening pcap file\n");
        ssh_pcap_file_free(sdata->pcap);
        sdata->pcap = NULL;
        return;
    }
    ssh_set_pcap_file(session, sdata->pcap);
}

static void cleanup_pcap(struct session_data_st *sdata)
{
    if (sdata == NULL) {
        return;
    }

    if (sdata->pcap == NULL) {
        return;
    }

    ssh_pcap_file_free(sdata->pcap);
    sdata->pcap = NULL;
}
#endif


/* The caller is responsible to set the userdata to be provided to the callback
 * The caller is responsible to free the allocated structure
 * */
struct ssh_server_callbacks_struct *get_sftp_server_cb(void)
{

    struct ssh_server_callbacks_struct *cb;

    cb = (struct ssh_server_callbacks_struct *)calloc(1,
            sizeof(struct ssh_server_callbacks_struct));

    if (cb == NULL) {
        fprintf(stderr, "Out of memory\n");
        goto end;
    }

    cb->auth_password_function = sftp_auth_password_cb;
    cb->channel_open_request_session_function = sftp_channel_new_session_cb;

end:
    return cb;
}

/* The caller is responsible to set the userdata to be provided to the callback
 * The caller is responsible to free the allocated structure
 * */
struct ssh_channel_callbacks_struct *get_sftp_channel_cb(void)
{
    struct ssh_channel_callbacks_struct *cb;

    cb = (struct ssh_channel_callbacks_struct *)calloc(1,
            sizeof(struct ssh_channel_callbacks_struct));
    if (cb == NULL) {
        fprintf(stderr, "Out of memory\n");
        goto end;
    }

    cb->channel_subsystem_request_function = sftp_channel_subsystem_request_cb;
    cb->channel_data_function = sftp_channel_data_cb;

end:
    return cb;
};

void sftp_handle_session_cb(ssh_event event,
                               ssh_session session,
                               struct server_state_st *state)
{
    int n;
    int rc = 0;

    /* Structure for storing the pty size. */
    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    /* Our struct holding information about the channel. */
    struct channel_data_st cdata = {
        .pid = 0,
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = NULL,
        .winsize = &wsize,
        .sftp = NULL
    };

    /* Our struct holding information about the session. */
    struct session_data_st sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0,
        .username = SSHD_DEFAULT_USER,
        .password = SSHD_DEFAULT_PASSWORD
    };

    struct ssh_channel_callbacks_struct *channel_cb = NULL;
    struct ssh_server_callbacks_struct *server_cb = NULL;

    if (state == NULL) {
        fprintf(stderr, "NULL server state provided\n");
        goto end;
    }

    /* If callbacks were provided use them. Otherwise, use default callbacks */
    if (state->server_cb != NULL) {
        /* This is a macro, it does not return a value */
        ssh_callbacks_init(state->server_cb);

        rc = ssh_set_server_callbacks(session, state->server_cb);
        if (rc) {
            goto end;
        }
    } else {
        server_cb = get_sftp_server_cb();
        if (server_cb == NULL) {
            goto end;
        }

        server_cb->userdata = &sdata;

        /* This is a macro, it does not return a value */
        ssh_callbacks_init(server_cb);

        rc = ssh_set_server_callbacks(session, server_cb);
        if (rc) {
            goto end;
        }
    }

    sdata.server_state = (void *)state;
    cdata.server_state = (void *)state;

#ifdef WITH_PCAP
    set_pcap(&sdata, session, state->pcap_file);
#endif

    if (state->expected_username != NULL) {
        sdata.username = state->expected_username;
    }

    if (state->expected_password != NULL) {
        sdata.password = state->expected_password;
    }

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        return;
    }

    /* Set the supported authentication methods */
    if (state->auth_methods) {
        ssh_set_auth_methods(session, state->auth_methods);
    } else {
        ssh_set_auth_methods(session,
                SSH_AUTH_METHOD_PASSWORD |
                SSH_AUTH_METHOD_PUBLICKEY);
    }

    ssh_event_add_session(event, session);

    n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 10 seconds (n * 100ms), disconnect. */
        if (sdata.auth_attempts >= state->max_tries || n >= 100) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "do_poll error: %s\n", ssh_get_error(session));
            return;
        }
        n++;
    }

    /* TODO check return values */
    if (state->channel_cb != NULL) {
        ssh_callbacks_init(state->channel_cb);

        rc = ssh_set_channel_callbacks(sdata.channel, state->channel_cb);
        if (rc) {
            goto end;
        }
    } else {
        channel_cb = get_sftp_channel_cb();
        if (channel_cb == NULL) {
            goto end;
        }

        channel_cb->userdata = &cdata;

        ssh_callbacks_init(channel_cb);
        rc = ssh_set_channel_callbacks(sdata.channel, channel_cb);
        if (rc) {
            goto end;
        }
    }

    do {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
          ssh_channel_close(sdata.channel);
        }

        /* If child process's stdout/stderr has been registered with the event,
         * or the child process hasn't started yet, continue. */
        if (cdata.event != NULL || cdata.pid == 0) {
            continue;
        }

    } while(ssh_channel_is_open(sdata.channel) &&
            (cdata.pid == 0 || waitpid(cdata.pid, &rc, WNOHANG) == 0));

    free_handles(MAX_HANDLE_NUM);
    
    ssh_channel_send_eof(sdata.channel);
    ssh_channel_close(sdata.channel);

    /* Wait up to 5 seconds for the client to terminate the session. */
    for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
        ssh_event_dopoll(event, 100);
    }

end:
#ifdef WITH_PCAP
    cleanup_pcap(&sdata);
#endif
    if (channel_cb != NULL) {
        free(channel_cb);
    }
    if (server_cb != NULL) {
        free(server_cb);
    }
    return;
}
