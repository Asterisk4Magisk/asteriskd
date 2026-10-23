// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int fail(char *error, size_t error_size, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    asteriskd_error_vformat(error, error_size, format, arguments);
    va_end(arguments);
    return ASTERISKD_CONFIG_IO;
}

static bool backend_valid(const struct asteriskd_bpf_pin_ownership_backend *backend) {
    return backend != NULL && backend->probe != NULL && backend->unlink_exact != NULL;
}

static int preflight_paths(
    const char *const *paths,
    size_t count,
    const struct asteriskd_bpf_pin_ownership_backend *backend,
    char *error,
    size_t error_size) {
    if (!backend_valid(backend) || paths == NULL || count == 0U) {
        return ASTERISKD_CONFIG_INVALID;
    }
    for (size_t left = 0U; left < count; ++left) {
        if (paths[left] == NULL || paths[left][0] != '/') return ASTERISKD_CONFIG_INVALID;
        for (size_t right = 0U; right < left; ++right) {
            if (strcmp(paths[left], paths[right]) == 0) return ASTERISKD_CONFIG_INVALID;
        }
        bool exists = true;
        uint64_t object_id = UINT64_MAX;
        if (backend->probe(backend->context, paths[left], &exists, &object_id) != 0) {
            return fail(error, error_size, "cannot inspect BPF pin %s", paths[left]);
        }
        if (exists) {
            return fail(error, error_size, "foreign or stale BPF pin blocks start: %s", paths[left]);
        }
        if (object_id != 0U) return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

int asteriskd_matcher_pin_preflight(
    const struct asteriskd_matcher_pin_plan *plan,
    const struct asteriskd_bpf_pin_ownership_backend *backend,
    char *error,
    size_t error_size) {
    if (plan == NULL || (plan->pin_count < 2U || plan->pin_count > 5U)) {
        return ASTERISKD_CONFIG_INVALID;
    }
    const char *paths[5U];
    for (size_t index = 0U; index < plan->pin_count; ++index) paths[index] = plan->pins[index].path;
    return preflight_paths(paths, plan->pin_count, backend, error, error_size);
}

int asteriskd_b2s_pin_preflight(
    const struct asteriskd_b2s_pin_plan *plan,
    const struct asteriskd_bpf_pin_ownership_backend *backend,
    char *error,
    size_t error_size) {
    if (plan == NULL || (plan->pin_count != 3U && plan->pin_count != 4U)) {
        return ASTERISKD_CONFIG_INVALID;
    }
    const char *paths[4U];
    for (size_t index = 0U; index < plan->pin_count; ++index) paths[index] = plan->pins[index].path;
    return preflight_paths(paths, plan->pin_count, backend, error, error_size);
}
