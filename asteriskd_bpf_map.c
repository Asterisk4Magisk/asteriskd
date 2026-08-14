// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define inet_pton InetPtonA
#else
#include <arpa/inet.h>
#endif

struct asteriskd_lpm4_key_v2 {
    uint32_t prefix_length;
    unsigned char address[4U];
};

struct asteriskd_lpm6_key_v2 {
    uint32_t prefix_length;
    unsigned char address[16U];
};

_Static_assert(sizeof(struct asteriskd_lpm4_key_v2) == 8U, "IPv4 LPM key ABI");
_Static_assert(sizeof(struct asteriskd_lpm6_key_v2) == 20U, "IPv6 LPM key ABI");

static void bpf_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) (void)snprintf(error, error_size, "%s", message);
}

static bool backend_valid(const struct asteriskd_bpf_map_backend *backend) {
    return backend != NULL && backend->open_pinned != NULL && backend->get_info != NULL &&
        backend->update != NULL && backend->get_next != NULL && backend->delete_key != NULL &&
        backend->close != NULL;
}

static bool map_info_valid(
    const struct asteriskd_bpf_map_info *info,
    uint64_t expected_object_id,
    size_t key_size) {
    return info->object_id == expected_object_id && expected_object_id != 0U &&
        info->type == ASTERISKD_BPF_MAP_TYPE_LPM_TRIE && info->key_size == key_size &&
        info->value_size == 1U && info->max_entries == ASTERISKD_BPF_LOCAL_MAP_MAX_ENTRIES &&
        info->flags == ASTERISKD_BPF_MAP_FLAG_NO_PREALLOC;
}

static int parse_address_key(
    int family,
    const char *address,
    void *key,
    size_t key_size) {
    memset(key, 0, key_size);
    if (family == ASTERISKD_ADDRESS_IPV4 && key_size == sizeof(struct asteriskd_lpm4_key_v2)) {
        struct asteriskd_lpm4_key_v2 *ipv4 = key;
        ipv4->prefix_length = 32U;
        return inet_pton(AF_INET, address, ipv4->address) == 1 ? 0 : -1;
    }
    if (family == ASTERISKD_ADDRESS_IPV6 && key_size == sizeof(struct asteriskd_lpm6_key_v2)) {
        struct asteriskd_lpm6_key_v2 *ipv6 = key;
        ipv6->prefix_length = 128U;
        return inet_pton(AF_INET6, address, ipv6->address) == 1 ? 0 : -1;
    }
    return -1;
}

static bool desired_contains(
    const unsigned char *desired,
    size_t desired_count,
    size_t key_size,
    const void *key) {
    for (size_t index = 0U; index < desired_count; ++index) {
        if (memcmp(desired + index * key_size, key, key_size) == 0) return true;
    }
    return false;
}

int asteriskd_bpf_local_map_reconcile(
    const struct asteriskd_bpf_map_backend *backend,
    const char *pin_path,
    uint64_t expected_object_id,
    const struct asteriskd_address_set *addresses,
    char *error,
    size_t error_size) {
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (!backend_valid(backend) || pin_path == NULL || pin_path[0] != '/' ||
        expected_object_id == 0U || addresses == NULL ||
        addresses->count > ASTERISKD_MAX_ADDRESSES ||
        (addresses->family != ASTERISKD_ADDRESS_IPV4 &&
         addresses->family != ASTERISKD_ADDRESS_IPV6)) {
        bpf_error(error, error_size, "invalid BPF map reconcile input");
        return ASTERISKD_CONFIG_INVALID;
    }
    size_t key_size = addresses->family == ASTERISKD_ADDRESS_IPV4 ?
        sizeof(struct asteriskd_lpm4_key_v2) : sizeof(struct asteriskd_lpm6_key_v2);
    unsigned char *desired = addresses->count == 0U ? NULL : calloc(addresses->count, key_size);
    unsigned char *existing = calloc(ASTERISKD_BPF_LOCAL_MAP_MAX_ENTRIES + 1U, key_size);
    if ((addresses->count != 0U && desired == NULL) || existing == NULL) {
        free(existing);
        free(desired);
        bpf_error(error, error_size, "BPF map reconcile allocation failed");
        return ASTERISKD_CONFIG_NO_MEMORY;
    }
    for (size_t index = 0U; index < addresses->count; ++index) {
        if (parse_address_key(addresses->family, addresses->values[index],
                desired + index * key_size, key_size) != 0) {
            free(existing);
            free(desired);
            bpf_error(error, error_size, "invalid local address");
            return ASTERISKD_CONFIG_INVALID;
        }
    }

    int map_fd = -1;
    int result = ASTERISKD_CONFIG_IO;
    if (backend->open_pinned(backend->context, pin_path, &map_fd) != 0 || map_fd < 0) {
        bpf_error(error, error_size, "open pinned BPF map failed");
        goto done;
    }
    struct asteriskd_bpf_map_info info;
    memset(&info, 0, sizeof(info));
    if (backend->get_info(backend->context, map_fd, &info) != 0 ||
        !map_info_valid(&info, expected_object_id, key_size)) {
        bpf_error(error, error_size, "pinned BPF map identity mismatch");
        goto done;
    }
    static const unsigned char value = 1U;
    for (size_t index = 0U; index < addresses->count; ++index) {
        if (backend->update(backend->context, map_fd, desired + index * key_size,
                key_size, &value, sizeof(value)) != 0) {
            bpf_error(error, error_size, "BPF map update failed");
            goto done;
        }
    }
    size_t existing_count = 0U;
    while (true) {
        bool has_next = false;
        void *current = existing_count == 0U ? NULL : existing + (existing_count - 1U) * key_size;
        if (backend->get_next(backend->context, map_fd, current, key_size,
                existing + existing_count * key_size, &has_next) != 0) {
            bpf_error(error, error_size, "BPF map enumeration failed");
            goto done;
        }
        if (!has_next) break;
        if (existing_count >= ASTERISKD_BPF_LOCAL_MAP_MAX_ENTRIES) {
            bpf_error(error, error_size, "BPF map contains too many entries");
            goto done;
        }
        ++existing_count;
    }
    for (size_t index = 0U; index < existing_count; ++index) {
        const void *key = existing + index * key_size;
        if (!desired_contains(desired, addresses->count, key_size, key) &&
            backend->delete_key(backend->context, map_fd, key, key_size) != 0) {
            bpf_error(error, error_size, "BPF map delete failed");
            goto done;
        }
    }
    result = 0;

done:
    if (map_fd >= 0 && backend->close(backend->context, map_fd) != 0 && result == 0) {
        bpf_error(error, error_size, "close pinned BPF map failed");
        result = ASTERISKD_CONFIG_IO;
    }
    free(existing);
    free(desired);
    return result;
}
