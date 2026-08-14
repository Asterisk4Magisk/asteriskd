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

#define MATCHER_KEY_STRIDE 20U

enum matcher_map_role {
    MATCHER_MAP_UID,
    MATCHER_MAP_DIRECT_V4,
    MATCHER_MAP_DIRECT_V6,
};

static void verify_error(char *error, size_t capacity, const char *message) {
    if (error != NULL && capacity != 0U) (void)snprintf(error, capacity, "%s", message);
}

static bool backend_valid(const struct asteriskd_bpf_program_backend *backend) {
    return backend != NULL && backend->open_program != NULL && backend->program_info != NULL &&
        backend->open_map != NULL && backend->map_info != NULL && backend->map_next != NULL &&
        backend->map_lookup != NULL && backend->close != NULL;
}

static bool tag_nonzero(const unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE]) {
    for (size_t index = 0U; index < ASTERISKD_BPF_PROGRAM_TAG_SIZE; ++index) {
        if (tag[index] != 0U) return true;
    }
    return false;
}

static int key_compare(const void *left, const void *right) {
    return memcmp(left, right, MATCHER_KEY_STRIDE);
}

static int parse_cidr_key(const char *cidr, int family, unsigned char key[MATCHER_KEY_STRIDE]) {
    memset(key, 0, MATCHER_KEY_STRIDE);
    const char *slash = strchr(cidr, '/');
    if (slash == NULL || slash == cidr || strchr(slash + 1, '/') != NULL) return -1;
    size_t address_length = (size_t)(slash - cidr);
    if (address_length >= ASTERISKD_MAX_CIDR) return -1;
    char address[ASTERISKD_MAX_CIDR];
    memcpy(address, cidr, address_length);
    address[address_length] = '\0';
    char *end = NULL;
    unsigned long prefix = strtoul(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0' ||
        (family == ASTERISKD_ADDRESS_IPV4 && prefix > 32U) ||
        (family == ASTERISKD_ADDRESS_IPV6 && prefix > 128U)) return -1;
    uint32_t prefix32 = (uint32_t)prefix;
    memcpy(key, &prefix32, sizeof(prefix32));
    int address_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    return inet_pton(address_family, address, key + sizeof(prefix32)) == 1 ? 0 : -1;
}

static int build_expected_keys(
    const struct asteriskd_config *config, enum matcher_map_role role,
    unsigned char **keys, size_t *count, size_t *key_size, size_t *value_size) {
    *keys = NULL;
    *count = 0U;
    if (role == MATCHER_MAP_UID) {
        size_t extra = config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST ? 2U : 0U;
        if (config->uid_count > SIZE_MAX - extra) return ASTERISKD_CONFIG_INVALID;
        size_t capacity = config->uid_count + extra;
        unsigned char *result = capacity == 0U ? NULL : calloc(capacity, MATCHER_KEY_STRIDE);
        if (capacity != 0U && result == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
        size_t length = 0U;
        for (size_t index = 0U; index < config->uid_count; ++index) {
            memcpy(result + length++ * MATCHER_KEY_STRIDE, &config->uids[index], sizeof(uint32_t));
        }
        if (extra != 0U) {
            uint32_t root_uid = 0U;
            uint32_t dns_uid = 1052U;
            memcpy(result + length++ * MATCHER_KEY_STRIDE, &root_uid, sizeof(root_uid));
            memcpy(result + length++ * MATCHER_KEY_STRIDE, &dns_uid, sizeof(dns_uid));
        }
        if (length > 1U) qsort(result, length, MATCHER_KEY_STRIDE, key_compare);
        size_t unique = 0U;
        for (size_t index = 0U; index < length; ++index) {
            if (unique == 0U || memcmp(result + index * MATCHER_KEY_STRIDE,
                result + (unique - 1U) * MATCHER_KEY_STRIDE, MATCHER_KEY_STRIDE) != 0) {
                if (unique != index) memcpy(result + unique * MATCHER_KEY_STRIDE,
                    result + index * MATCHER_KEY_STRIDE, MATCHER_KEY_STRIDE);
                ++unique;
            }
        }
        *keys = result;
        *count = unique;
        *key_size = 4U;
        *value_size = 4U;
        return 0;
    }
    if (config->direct_cidrs == NULL) return ASTERISKD_CONFIG_INVALID;
    bool ipv4 = role == MATCHER_MAP_DIRECT_V4;
    size_t length = ipv4 ? config->direct_cidrs->ipv4_count : config->direct_cidrs->ipv6_count;
    const char (*values)[ASTERISKD_MAX_CIDR] = ipv4 ?
        config->direct_cidrs->ipv4 : config->direct_cidrs->ipv6;
    unsigned char *result = length == 0U ? NULL : calloc(length, MATCHER_KEY_STRIDE);
    if (length != 0U && result == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    for (size_t index = 0U; index < length; ++index) {
        if (parse_cidr_key(values[index], ipv4 ? ASTERISKD_ADDRESS_IPV4 :
            ASTERISKD_ADDRESS_IPV6, result + index * MATCHER_KEY_STRIDE) != 0) {
            free(result);
            return ASTERISKD_CONFIG_INVALID;
        }
    }
    if (length > 1U) qsort(result, length, MATCHER_KEY_STRIDE, key_compare);
    *keys = result;
    *count = length;
    *key_size = ipv4 ? 8U : 20U;
    *value_size = 1U;
    return 0;
}

static bool map_info_matches(
    const struct asteriskd_bpf_map_info *info, uint32_t id, enum matcher_map_role role) {
    if (info->object_id != id) return false;
    if (role == MATCHER_MAP_UID) {
        return info->type == ASTERISKD_BPF_MAP_TYPE_HASH && info->key_size == 4U &&
            info->value_size == 4U && info->max_entries == ASTERISKD_MATCHER_UID_MAP_MAX_ENTRIES &&
            info->flags == 0U;
    }
    return info->type == ASTERISKD_BPF_MAP_TYPE_LPM_TRIE &&
        info->key_size == (role == MATCHER_MAP_DIRECT_V4 ? 8U : 20U) &&
        info->value_size == 1U && info->max_entries == ASTERISKD_MATCHER_DIRECT_MAP_MAX_ENTRIES &&
        info->flags == ASTERISKD_BPF_MAP_FLAG_NO_PREALLOC;
}

static int verify_map(
    const struct asteriskd_config *config, const struct asteriskd_bpf_program_backend *backend,
    uint32_t id, enum matcher_map_role role) {
    unsigned char *expected = NULL;
    size_t expected_count = 0U;
    size_t key_size = 0U;
    size_t value_size = 0U;
    int result = build_expected_keys(config, role, &expected, &expected_count, &key_size, &value_size);
    if (result != 0) return result;
    bool *seen = expected_count == 0U ? NULL : calloc(expected_count, sizeof(*seen));
    if (expected_count != 0U && seen == NULL) {
        free(expected);
        return ASTERISKD_CONFIG_NO_MEMORY;
    }
    int fd = -1;
    result = ASTERISKD_CONFIG_IO;
    if (backend->open_map(backend->context, id, &fd) != 0 || fd < 0) goto done;
    struct asteriskd_bpf_map_info info;
    memset(&info, 0, sizeof(info));
    if (backend->map_info(backend->context, fd, &info) != 0 || !map_info_matches(&info, id, role)) {
        goto done;
    }
    unsigned char current[MATCHER_KEY_STRIDE];
    unsigned char next[MATCHER_KEY_STRIDE];
    memset(current, 0, sizeof(current));
    size_t actual_count = 0U;
    while (true) {
        memset(next, 0, sizeof(next));
        bool has_next = false;
        if (backend->map_next(backend->context, fd, actual_count == 0U ? NULL : current,
            key_size, next, &has_next) != 0) goto done;
        if (!has_next) break;
        if (actual_count >= expected_count) goto done;
        unsigned char lookup_key[MATCHER_KEY_STRIDE];
        memset(lookup_key, 0, sizeof(lookup_key));
        memcpy(lookup_key, next, key_size);
        unsigned char *match = bsearch(
            lookup_key, expected, expected_count, MATCHER_KEY_STRIDE, key_compare);
        if (match == NULL) goto done;
        size_t match_index = (size_t)(match - expected) / MATCHER_KEY_STRIDE;
        if (seen[match_index]) goto done;
        unsigned char value[4U] = {0U, 0U, 0U, 0U};
        bool found = false;
        if (backend->map_lookup(backend->context, fd, next, key_size,
            value, value_size, &found) != 0 || !found || value[0] != 1U) goto done;
        for (size_t byte = 1U; byte < value_size; ++byte) {
            if (value[byte] != 0U) goto done;
        }
        seen[match_index] = true;
        memcpy(current, next, key_size);
        ++actual_count;
    }
    if (actual_count != expected_count) goto done;
    for (size_t index = 0U; index < expected_count; ++index) {
        if (!seen[index]) goto done;
    }
    result = 0;

done:
    if (fd >= 0 && backend->close(backend->context, fd) != 0 && result == 0) {
        result = ASTERISKD_CONFIG_IO;
    }
    free(seen);
    free(expected);
    return result;
}

static int pin_shape(
    enum asteriskd_pin_id pin_id, bool *output, enum matcher_map_role *direct_role) {
    switch (pin_id) {
        case ASTERISKD_PIN_MATCHER_OUTPUT_V4:
            *output = true;
            *direct_role = MATCHER_MAP_DIRECT_V4;
            return 0;
        case ASTERISKD_PIN_MATCHER_OUTPUT_V6:
            *output = true;
            *direct_role = MATCHER_MAP_DIRECT_V6;
            return 0;
        case ASTERISKD_PIN_MATCHER_PREROUTING_V4:
            *output = false;
            *direct_role = MATCHER_MAP_DIRECT_V4;
            return 0;
        case ASTERISKD_PIN_MATCHER_PREROUTING_V6:
            *output = false;
            *direct_role = MATCHER_MAP_DIRECT_V6;
            return 0;
        default:
            return -1;
    }
}

int asteriskd_matcher_verify(
    const struct asteriskd_config *config, const struct asteriskd_matcher_pin_plan *plan,
    const struct asteriskd_bpf_program_backend *backend,
    struct asteriskd_matcher_verification *verification, char *error, size_t error_capacity) {
    if (verification != NULL) memset(verification, 0, sizeof(*verification));
    if (error != NULL && error_capacity != 0U) error[0] = '\0';
    if (config == NULL || plan == NULL || verification == NULL || !config->matcher.enabled ||
        !backend_valid(backend) || plan->pin_count != (config->enable_ipv6 ? 4U : 2U)) {
        verify_error(error, error_capacity, "invalid matcher verification input");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_matcher_verification result;
    memset(&result, 0, sizeof(result));
    uint32_t uid_map_id = 0U;
    uint32_t direct_v4_id = 0U;
    uint32_t direct_v6_id = 0U;
    for (size_t index = 0U; index < plan->pin_count; ++index) {
        bool output = false;
        enum matcher_map_role direct_role;
        if (pin_shape(plan->pins[index].pin_id, &output, &direct_role) != 0) goto mismatch;
        int program_fd = -1;
        int item_result = ASTERISKD_CONFIG_IO;
        if (backend->open_program(backend->context, plan->pins[index].path, &program_fd) != 0 ||
            program_fd < 0) goto program_done;
        struct asteriskd_bpf_program_info info;
        memset(&info, 0, sizeof(info));
        if (backend->program_info(backend->context, program_fd, &info) != 0 ||
            info.object_id == 0U || info.type != ASTERISKD_BPF_PROGRAM_TYPE_SOCKET_FILTER ||
            strcmp(info.name, plan->pins[index].program_name) != 0 || !tag_nonzero(info.tag) ||
            info.map_count > ASTERISKD_BPF_PROGRAM_MAX_MAPS) goto program_done;
        bool needs_uid = output && config->app_policy_mode != ASTERISKD_APP_POLICY_GLOBAL;
        bool needs_direct = config->direct_cidrs != NULL;
        size_t expected_maps = (needs_uid ? 1U : 0U) + (needs_direct ? 1U : 0U);
        if (info.map_count != expected_maps) goto program_done;
        size_t map_index = 0U;
        if (needs_uid) {
            uint32_t id = info.map_ids[map_index++];
            if (id == 0U || (uid_map_id != 0U && uid_map_id != id) ||
                verify_map(config, backend, id, MATCHER_MAP_UID) != 0) goto program_done;
            uid_map_id = id;
        }
        if (needs_direct) {
            uint32_t id = info.map_ids[map_index];
            uint32_t *known = direct_role == MATCHER_MAP_DIRECT_V4 ? &direct_v4_id : &direct_v6_id;
            if (id == 0U || (*known != 0U && *known != id) ||
                verify_map(config, backend, id, direct_role) != 0) goto program_done;
            *known = id;
        }
        result.pins[index].pin_id = plan->pins[index].pin_id;
        result.pins[index].object_id = info.object_id;
        memcpy(result.pins[index].tag, info.tag, sizeof(info.tag));
        ++result.pin_count;
        item_result = 0;

program_done:
        if (program_fd >= 0 && backend->close(backend->context, program_fd) != 0 &&
            item_result == 0) item_result = ASTERISKD_CONFIG_IO;
        if (item_result != 0) goto mismatch;
    }
    *verification = result;
    return 0;

mismatch:
    verify_error(error, error_capacity, "matcher pin or map verification failed");
    return ASTERISKD_CONFIG_IO;
}
