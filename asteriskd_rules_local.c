#include "asteriskd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define inet_pton InetPtonA
#define inet_ntop InetNtopA
#else
#include <arpa/inet.h>
#endif

struct binary_address {
    unsigned char bytes[16U];
};

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != NULL && capacity != 0U) (void)snprintf(error, capacity, "%s", message);
}

static bool interface_name_valid(const char *name) {
    size_t length = name == NULL ? 0U : strnlen(name, ASTERISKD_MAX_INTERFACE_NAME);
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return false;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char byte = (unsigned char)name[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9') || byte == '_' || byte == '-' || byte == '.')) {
            return false;
        }
    }
    return true;
}

static bool excluded_interface(const struct asteriskd_config *config, const char *name) {
    if (strcmp(name, "all") == 0 || strcmp(name, "default") == 0 || strcmp(name, "lo") == 0) {
        return true;
    }
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (strcmp(name, config->ignored_interfaces[index]) == 0) return true;
    }
    for (size_t index = 0U; index < config->virtual_interface_count; ++index) {
        if (strcmp(name, config->virtual_interfaces[index]) == 0) return true;
    }
    return false;
}

static bool unspecified(const unsigned char *bytes, size_t length) {
    for (size_t index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

static bool multicast(int family, const unsigned char *bytes) {
    return family == ASTERISKD_ADDRESS_IPV4 ? (bytes[0] & 0xf0U) == 0xe0U : bytes[0] == 0xffU;
}

static int binary_compare(const void *left, const void *right) {
    return memcmp(left, right, sizeof(struct binary_address));
}

int asteriskd_local_address_set_build(
    const struct asteriskd_config *config, int family,
    const struct asteriskd_interface_address *candidates, size_t candidate_count,
    struct asteriskd_address_set *set, char *error, size_t error_capacity) {
    if (set == NULL) {
        set_error(error, error_capacity, "local address output is required");
        return ASTERISKD_CONFIG_INVALID;
    }
    memset(set, 0, sizeof(*set));
    if (config == NULL || (candidate_count != 0U && candidates == NULL) ||
        (family != ASTERISKD_ADDRESS_IPV4 && family != ASTERISKD_ADDRESS_IPV6)) {
        set_error(error, error_capacity, "invalid local address input");
        return ASTERISKD_CONFIG_INVALID;
    }
    set->family = family;
    if (config->mode == ASTERISKD_MODE_EBPF) return 0;
    struct binary_address *desired = candidate_count == 0U ? NULL :
        calloc(candidate_count, sizeof(*desired));
    if (candidate_count != 0U && desired == NULL) {
        memset(set, 0, sizeof(*set));
        return ASTERISKD_CONFIG_NO_MEMORY;
    }
    size_t length = family == ASTERISKD_ADDRESS_IPV4 ? 4U : 16U;
    int native_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    size_t desired_count = 0U;
    for (size_t index = 0U; index < candidate_count; ++index) {
        if (!interface_name_valid(candidates[index].interface_name)) goto invalid;
        if (excluded_interface(config, candidates[index].interface_name)) continue;
        struct binary_address address;
        memset(&address, 0, sizeof(address));
        if (inet_pton(native_family, candidates[index].address, address.bytes) != 1) goto invalid;
        if (unspecified(address.bytes, length) || multicast(family, address.bytes)) continue;
        desired[desired_count++] = address;
    }
    if (desired_count > 1U) qsort(desired, desired_count, sizeof(*desired), binary_compare);
    size_t unique_count = 0U;
    for (size_t index = 0U; index < desired_count; ++index) {
        if (unique_count != 0U &&
            memcmp(&desired[index], &desired[unique_count - 1U], sizeof(*desired)) == 0) continue;
        if (unique_count >= ASTERISKD_MAX_ADDRESSES) {
            free(desired);
            memset(set, 0, sizeof(*set));
            set_error(error, error_capacity, "too many local addresses");
            return ASTERISKD_CONFIG_INVALID;
        }
        if (unique_count != index) desired[unique_count] = desired[index];
        ++unique_count;
    }
    for (size_t index = 0U; index < unique_count; ++index) {
        if (inet_ntop(native_family, desired[index].bytes,
            set->values[index], sizeof(set->values[index])) == NULL) goto invalid;
    }
    set->count = unique_count;
    free(desired);
    return 0;

invalid:
    free(desired);
    memset(set, 0, sizeof(*set));
    set_error(error, error_capacity, "invalid local interface address");
    return ASTERISKD_CONFIG_INVALID;
}
