/*
  acl_preserve.c -- verify that replacing an archive preserves its POSIX access ACL
  SPDX-License-Identifier: BSD-3-Clause
*/

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/types.h>

#include "zip.h"

static char *get_acl_text(const char *path) {
    acl_t acl;
    char *text;

    if ((acl = acl_get_file(path, ACL_TYPE_ACCESS)) == NULL) {
        return NULL;
    }
    text = acl_to_text(acl, NULL);
    (void)acl_free(acl);
    return text;
}

int main(void) {
    static const char archive_name[] = "acl-preserve.zip";
    static const char contents[] = "data";
    static const char acl_text[] = "u::rw-,u:65534:rw-,g::---,m::rw-,o::---";
    char *before = NULL;
    char *after = NULL;
    acl_t acl = NULL;
    zip_source_t *source = NULL;
    zip_t *archive = NULL;
    zip_error_t error;
    int error_code;
    int result = 1;

    (void)remove(archive_name);

    archive = zip_open(archive_name, ZIP_CREATE | ZIP_TRUNCATE, &error_code);
    if (archive == NULL) {
        fprintf(stderr, "cannot create archive: %d\n", error_code);
        goto done;
    }
    source = zip_source_buffer(archive, contents, sizeof(contents) - 1, 0);
    if (source == NULL || zip_file_add(archive, "data", source, 0) < 0) {
        fprintf(stderr, "cannot add archive entry\n");
        if (source != NULL) {
            zip_source_free(source);
            source = NULL;
        }
        zip_discard(archive);
        archive = NULL;
        goto done;
    }
    source = NULL; /* owned by archive */
    if (zip_close(archive) < 0) {
        fprintf(stderr, "cannot finish initial archive\n");
        zip_discard(archive);
        archive = NULL;
        goto done;
    }
    archive = NULL;

    if ((acl = acl_from_text(acl_text)) == NULL) {
        perror("cannot create test ACL");
        goto done;
    }
    if (acl_set_file(archive_name, ACL_TYPE_ACCESS, acl) < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM || errno == EINVAL) {
            result = 77;
            goto done;
        }
        perror("cannot set test ACL");
        goto done;
    }
    (void)acl_free(acl);
    acl = NULL;
    if ((before = get_acl_text(archive_name)) == NULL) {
        perror("cannot read ACL before replacement");
        goto done;
    }

    archive = zip_open(archive_name, 0, &error_code);
    if (archive == NULL) {
        fprintf(stderr, "cannot reopen archive: %d\n", error_code);
        goto done;
    }
    if (zip_set_archive_comment(archive, "changed", 7) < 0 || zip_close(archive) < 0) {
        fprintf(stderr, "cannot update archive\n");
        zip_discard(archive);
        archive = NULL;
        goto done;
    }
    archive = NULL;

    if ((after = get_acl_text(archive_name)) == NULL || strcmp(before, after) != 0) {
        fprintf(stderr, "POSIX access ACL changed during archive replacement\n");
        goto done;
    }
    (void)acl_free(after);
    after = NULL;

    zip_error_init(&error);
    source = zip_source_file_create(archive_name, 0, -1, &error);
    if (source == NULL) {
        fprintf(stderr, "cannot create named file source: %s\n", zip_error_strerror(&error));
        zip_error_fini(&error);
        goto done;
    }
    if (zip_source_begin_write(source) < 0 || zip_source_write(source, contents, sizeof(contents) - 1) != sizeof(contents) - 1 || zip_source_commit_write(source) < 0) {
        fprintf(stderr, "cannot replace named file source: %s\n", zip_error_strerror(zip_source_error(source)));
        zip_source_free(source);
        source = NULL;
        zip_error_fini(&error);
        goto done;
    }
    zip_source_free(source);
    source = NULL;
    zip_error_fini(&error);

    if ((after = get_acl_text(archive_name)) == NULL || strcmp(before, after) != 0) {
        fprintf(stderr, "POSIX access ACL changed during direct source replacement\n");
        goto done;
    }

    puts("POSIX access ACL preserved");
    result = 0;

done:
    if (archive != NULL) {
        zip_discard(archive);
    }
    if (source != NULL) {
        zip_source_free(source);
    }
    if (acl != NULL) {
        (void)acl_free(acl);
    }
    if (before != NULL) {
        (void)acl_free(before);
    }
    if (after != NULL) {
        (void)acl_free(after);
    }
    (void)remove(archive_name);
    return result;
}
