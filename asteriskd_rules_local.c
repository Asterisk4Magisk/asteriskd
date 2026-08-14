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

static bool address_set_contains(
    const struct asteriskd_address_set *set, const char *address) {
    for (size_t index = 0U; index < set->count; ++index) {
        if (strcmp(set->values[index], address) == 0) return true;
    }
    return false;
}

static int parse_host_cidr(
    int family, const char *cidr, char *address, size_t address_capacity) {
    char value[80U];
    int written = snprintf(value, sizeof(value), "%s", cidr);
    if (written <= 0 || (size_t)written >= sizeof(value)) return ASTERISKD_CONFIG_INVALID;
    char *slash = strchr(value, '/');
    if (slash == NULL || strchr(slash + 1, '/') != NULL) return ASTERISKD_CONFIG_INVALID;
    *slash++ = '\0';
    const char *expected_prefix = family == ASTERISKD_ADDRESS_IPV4 ? "32" : "128";
    if (strcmp(slash, expected_prefix) != 0) return ASTERISKD_CONFIG_INVALID;
    unsigned char binary[16U];
    int native_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    if (inet_pton(native_family, value, binary) != 1 ||
        inet_ntop(native_family, binary, address, address_capacity) == NULL) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

static int local_bypass_plan_append(
    struct asteriskd_local_bypass_plan *plan,
    enum asteriskd_local_bypass_operation_kind kind,
    size_t rule_number,
    const char *address) {
    if (plan->operation_count >= ASTERISKD_LOCAL_BYPASS_MAX_OPERATIONS) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_local_bypass_operation *operation =
        &plan->operations[plan->operation_count++];
    operation->kind = kind;
    operation->rule_number = rule_number;
    int written = snprintf(operation->address, sizeof(operation->address), "%s", address);
    return written > 0 && (size_t)written < sizeof(operation->address)
        ? 0 : ASTERISKD_CONFIG_INVALID;
}

int asteriskd_local_bypass_plan_build(
    int family,
    const char *consumer_chain,
    const char *begin_chain,
    const char *end_chain,
    const char *rules,
    size_t rules_length,
    const struct asteriskd_address_set *desired,
    struct asteriskd_local_bypass_plan *plan,
    char *error,
    size_t error_capacity) {
    if (plan != NULL) memset(plan, 0, sizeof(*plan));
    if (consumer_chain == NULL || begin_chain == NULL || end_chain == NULL ||
        rules == NULL || desired == NULL || plan == NULL || desired->family != family ||
        desired->count > ASTERISKD_MAX_ADDRESSES ||
        (family != ASTERISKD_ADDRESS_IPV4 && family != ASTERISKD_ADDRESS_IPV6)) {
        set_error(error, error_capacity, "invalid local bypass plan input");
        return ASTERISKD_CONFIG_INVALID;
    }
    char rule_prefix[ASTERISKD_MAX_CHAIN_NAME + 8U];
    char begin_rule[ASTERISKD_MAX_CHAIN_NAME * 2U + 16U];
    char end_rule[ASTERISKD_MAX_CHAIN_NAME * 2U + 16U];
    char destination_prefix[ASTERISKD_MAX_CHAIN_NAME + 12U];
    int prefix_length = snprintf(rule_prefix, sizeof(rule_prefix), "-A %s ", consumer_chain);
    int begin_length = snprintf(
        begin_rule, sizeof(begin_rule), "-A %s -j %s", consumer_chain, begin_chain);
    int end_length = snprintf(
        end_rule, sizeof(end_rule), "-A %s -j %s", consumer_chain, end_chain);
    int destination_prefix_length = snprintf(
        destination_prefix, sizeof(destination_prefix), "-A %s -d ", consumer_chain);
    if (prefix_length <= 0 || (size_t)prefix_length >= sizeof(rule_prefix) ||
        begin_length <= 0 || (size_t)begin_length >= sizeof(begin_rule) ||
        end_length <= 0 || (size_t)end_length >= sizeof(end_rule) ||
        destination_prefix_length <= 0 ||
        (size_t)destination_prefix_length >= sizeof(destination_prefix)) {
        set_error(error, error_capacity, "invalid local bypass chain name");
        return ASTERISKD_CONFIG_INVALID;
    }

    struct asteriskd_address_set current;
    memset(&current, 0, sizeof(current));
    current.family = family;
    bool begin_found = false;
    bool end_found = false;
    bool inside = false;
    size_t end_rule_number = 0U;
    size_t rule_number = 0U;
    size_t offset = 0U;
    static const char return_suffix[] = " -j RETURN";
    while (offset < rules_length) {
        const char *newline = memchr(rules + offset, '\n', rules_length - offset);
        size_t line_length = newline == NULL
            ? rules_length - offset : (size_t)(newline - (rules + offset));
        if (line_length != 0U && rules[offset + line_length - 1U] == '\r') --line_length;
        if (line_length >= 512U) {
            set_error(error, error_capacity, "local bypass rule is too long");
            return ASTERISKD_CONFIG_INVALID;
        }
        char line[512U];
        memcpy(line, rules + offset, line_length);
        line[line_length] = '\0';
        offset = newline == NULL ? rules_length : (size_t)(newline - rules) + 1U;
        if (strncmp(line, rule_prefix, (size_t)prefix_length) != 0) continue;
        ++rule_number;
        if (strcmp(line, begin_rule) == 0) {
            if (begin_found || end_found) {
                set_error(error, error_capacity, "invalid local bypass begin marker");
                return ASTERISKD_CONFIG_INVALID;
            }
            begin_found = true;
            inside = true;
            continue;
        }
        if (strcmp(line, end_rule) == 0) {
            if (!inside || end_found) {
                set_error(error, error_capacity, "invalid local bypass end marker");
                return ASTERISKD_CONFIG_INVALID;
            }
            end_found = true;
            inside = false;
            end_rule_number = rule_number;
            continue;
        }
        if (!inside) continue;
        if (strncmp(line, destination_prefix, (size_t)destination_prefix_length) != 0) {
            set_error(error, error_capacity, "foreign rule inside local bypass interval");
            return ASTERISKD_CONFIG_INVALID;
        }
        const char *cidr = line + destination_prefix_length;
        const char *suffix = strstr(cidr, return_suffix);
        if (suffix == NULL || suffix[sizeof(return_suffix) - 1U] != '\0' ||
            current.count >= ASTERISKD_MAX_ADDRESSES) {
            set_error(error, error_capacity, "invalid local bypass address rule");
            return ASTERISKD_CONFIG_INVALID;
        }
        size_t cidr_length = (size_t)(suffix - cidr);
        if (cidr_length == 0U || cidr_length >= 80U) {
            set_error(error, error_capacity, "invalid local bypass address cidr");
            return ASTERISKD_CONFIG_INVALID;
        }
        char cidr_value[80U];
        memcpy(cidr_value, cidr, cidr_length);
        cidr_value[cidr_length] = '\0';
        char address[64U];
        if (parse_host_cidr(family, cidr_value, address, sizeof(address)) != 0 ||
            address_set_contains(&current, address)) {
            set_error(error, error_capacity, "invalid local bypass host address");
            return ASTERISKD_CONFIG_INVALID;
        }
        (void)snprintf(current.values[current.count++], sizeof(current.values[0]), "%s", address);
    }
    if (!begin_found || !end_found || inside || end_rule_number == 0U) {
        set_error(error, error_capacity, "local bypass markers are missing or unordered");
        return ASTERISKD_CONFIG_INVALID;
    }
    for (size_t index = 0U; index < desired->count; ++index) {
        char address[64U];
        unsigned char binary[16U];
        int native_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
        if (inet_pton(native_family, desired->values[index], binary) != 1 ||
            inet_ntop(native_family, binary, address, sizeof(address)) == NULL) {
            set_error(error, error_capacity, "invalid desired local bypass address");
            return ASTERISKD_CONFIG_INVALID;
        }
        if (!address_set_contains(&current, address) && local_bypass_plan_append(
                plan, ASTERISKD_LOCAL_BYPASS_INSERT,
                end_rule_number, address) != 0) {
            set_error(error, error_capacity, "local bypass insertion plan overflow");
            return ASTERISKD_CONFIG_INVALID;
        }
    }
    for (size_t index = 0U; index < current.count; ++index) {
        if (!address_set_contains(desired, current.values[index]) && local_bypass_plan_append(
                plan, ASTERISKD_LOCAL_BYPASS_DELETE,
                0U, current.values[index]) != 0) {
            set_error(error, error_capacity, "local bypass deletion plan overflow");
            return ASTERISKD_CONFIG_INVALID;
        }
    }
    return 0;
}
