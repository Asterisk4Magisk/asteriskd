// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd_compat.h"

int asteriskd_bpf_pin_probe_with_backend(
    const struct asteriskd_bpf_pin_probe_backend *backend,
    const char *path, bool *exists, uint64_t *object_id) {
    if (exists != NULL) *exists = false;
    if (object_id != NULL) *object_id = 0U;
    if (backend == NULL || backend->inspect_path == NULL ||
        backend->open_pinned == NULL || backend->read_object_id == NULL ||
        backend->close_fd == NULL || path == NULL || path[0] != '/' ||
        exists == NULL || object_id == NULL) return -1;

    bool path_exists = false;
    if (backend->inspect_path(backend->context, path, &path_exists) != 0) return -1;
    if (!path_exists) return 0;

    int fd = -1;
    if (backend->open_pinned(backend->context, path, &fd) != 0 || fd < 0) return -1;
    uint64_t id = 0U;
    int read_result = backend->read_object_id(backend->context, fd, &id);
    int close_result = backend->close_fd(backend->context, fd);
    if (read_result != 0 || close_result != 0 || id == 0U) return -1;

    *exists = true;
    *object_id = id;
    return 0;
}
